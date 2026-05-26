package core

import (
	"strings"
	"testing"
	"time"
)

func TestHashPasswordRoundTrip(t *testing.T) {
	hashValue, err := HashPassword("Fm040924.")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hashValue, "$argon2id$") {
		t.Fatalf("hash = %q", hashValue)
	}
	if !VerifyPassword(hashValue, "Fm040924.") {
		t.Fatal("VerifyPassword should accept the original password")
	}
	if VerifyPassword(hashValue, "wrong-password") {
		t.Fatal("VerifyPassword should reject the wrong password")
	}
}

func TestHighRiskNaturalLanguageChallengeAndReplay(t *testing.T) {
	session := newResultAgentSession("done")
	agent := &resultAgent{session: session}
	p := &stubPlatformEngine{n: "test"}
	e := NewEngine("test", agent, []Platform{p}, "", LangEnglish)
	hashValue, err := HashPassword("Fm040924.")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	e.SetHighRiskAuthConfig(HighRiskAuthConfig{
		Enabled:      true,
		PasswordHash: hashValue,
	})

	e.ReceiveMessage(p, &Message{
		SessionKey: "test:user1",
		UserID:     "user1",
		Platform:   "test",
		ReplyCtx:   "ctx-risk",
		Content:    "把 /etc/nginx/nginx.conf 改成新的配置",
	})
	if len(session.sentPrompts) != 0 {
		t.Fatalf("agent should not receive blocked request, got %v", session.sentPrompts)
	}
	sent := p.getSent()
	if len(sent) != 1 || !strings.Contains(sent[0], "高风险密码") {
		t.Fatalf("challenge reply = %v", sent)
	}

	p.clearSent()
	e.ReceiveMessage(p, &Message{
		SessionKey: "test:user1",
		UserID:     "user1",
		Platform:   "test",
		ReplyCtx:   "ctx-auth",
		Content:    "Fm040924.",
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(session.sentPrompts) == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(session.sentPrompts) != 1 {
		t.Fatalf("expected replay to reach agent, got %v", session.sentPrompts)
	}
	if !strings.Contains(session.sentPrompts[0], "/etc/nginx/nginx.conf") {
		t.Fatalf("replayed prompt = %q", session.sentPrompts[0])
	}
}

func TestHighRiskShowCommandBlockedUntilPassword(t *testing.T) {
	p := &stubPlatformEngine{n: "test"}
	e := NewEngine("test", &stubAgent{}, []Platform{p}, "", LangEnglish)
	e.SetAdminFrom("user1")
	hashValue, err := HashPassword("Fm040924.")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	e.SetHighRiskAuthConfig(HighRiskAuthConfig{
		Enabled:      true,
		PasswordHash: hashValue,
	})

	msg := &Message{
		SessionKey: "test:user1",
		UserID:     "user1",
		Platform:   "test",
		ReplyCtx:   "ctx",
		Content:    "/show /etc/nginx/nginx.conf",
	}
	e.handleCommand(p, msg, msg.Content)
	sent := p.getSent()
	if len(sent) != 1 || !strings.Contains(sent[0], "高风险密码") {
		t.Fatalf("challenge reply = %v", sent)
	}
}

func TestHighRiskFailureLimitAndExpiry(t *testing.T) {
	p := &stubPlatformEngine{n: "test"}
	e := NewEngine("test", &stubAgent{}, []Platform{p}, "", LangEnglish)
	hashValue, err := HashPassword("Fm040924.")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	e.SetHighRiskAuthConfig(HighRiskAuthConfig{
		Enabled:        true,
		PasswordHash:   hashValue,
		PendingTTLSecs: 10,
		MaxFailures:    2,
	})

	e.ReceiveMessage(p, &Message{
		SessionKey: "test:user1",
		UserID:     "user1",
		Platform:   "test",
		ReplyCtx:   "ctx-risk",
		Content:    "查看 /srv/projects/proxy/stack/nginx.conf",
	})
	p.clearSent()

	e.ReceiveMessage(p, &Message{
		SessionKey: "test:user1",
		UserID:     "user1",
		Platform:   "test",
		ReplyCtx:   "ctx-auth-1",
		Content:    "wrong",
	})
	sent := p.getSent()
	if len(sent) != 1 || !strings.Contains(sent[0], "密码错误") {
		t.Fatalf("first failure reply = %v", sent)
	}

	p.clearSent()
	e.ReceiveMessage(p, &Message{
		SessionKey: "test:user1",
		UserID:     "user1",
		Platform:   "test",
		ReplyCtx:   "ctx-auth-2",
		Content:    "still-wrong",
	})
	sent = p.getSent()
	if len(sent) != 1 || !strings.Contains(sent[0], "已失效") {
		t.Fatalf("second failure reply = %v", sent)
	}
	state := e.highRiskStates["user1"]
	if state == nil || state.Pending != nil {
		t.Fatalf("pending request should be cleared after max failures, state=%+v", state)
	}

	e.ReceiveMessage(p, &Message{
		SessionKey: "test:user1",
		UserID:     "user1",
		Platform:   "test",
		ReplyCtx:   "ctx-risk-2",
		Content:    "查看 /etc/nginx/nginx.conf",
	})
	state = e.highRiskStates["user1"]
	if state == nil || state.Pending == nil {
		t.Fatalf("expected pending request, state=%+v", state)
	}
	state.UnlockedUntil = time.Time{}
	state.Pending.CreatedAt = time.Now().Add(-11 * time.Second)
	p.clearSent()

	e.ReceiveMessage(p, &Message{
		SessionKey: "test:user1",
		UserID:     "user1",
		Platform:   "test",
		ReplyCtx:   "ctx-expired",
		Content:    "Fm040924.",
	})
	sent = p.getSent()
	if len(sent) != 1 || !strings.Contains(sent[0], "已过期") {
		t.Fatalf("expired reply = %v", sent)
	}
}
