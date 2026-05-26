package core

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	defaultHighRiskUnlockWindowSecs = 600
	defaultHighRiskPendingTTLSecs   = 180
	defaultHighRiskMaxFailures      = 3
	defaultHighRiskChallengePrompt  = "检测到高风险操作，请直接回复高风险密码完成授权。"
)

var (
	highRiskProtectedProjectStackRe = regexp.MustCompile(`^/srv/projects/[^/]+/stack(?:/|$)`)
	highRiskSensitiveValueRe        = regexp.MustCompile(`(?i)(token|secret|password|api[_-]?key|auth)\s*([:=]\s*|\s+)\S+`)
)

type HighRiskAuthConfig struct {
	Enabled          bool
	PasswordHash     string
	UnlockWindowSecs int
	PendingTTLSecs   int
	MaxFailures      int
	ChallengePrompt  string
	Scope            string
}

type highRiskUserState struct {
	UnlockedUntil time.Time
	Pending       *highRiskPendingRequest
}

type highRiskPendingRequest struct {
	Message      Message
	CreatedAt    time.Time
	FailureCount int
	Summary      string
}

func normalizeHighRiskAuthConfig(cfg HighRiskAuthConfig) HighRiskAuthConfig {
	cfg.PasswordHash = strings.TrimSpace(cfg.PasswordHash)
	if cfg.UnlockWindowSecs <= 0 {
		cfg.UnlockWindowSecs = defaultHighRiskUnlockWindowSecs
	}
	if cfg.PendingTTLSecs <= 0 {
		cfg.PendingTTLSecs = defaultHighRiskPendingTTLSecs
	}
	if cfg.MaxFailures <= 0 {
		cfg.MaxFailures = defaultHighRiskMaxFailures
	}
	if strings.TrimSpace(cfg.ChallengePrompt) == "" {
		cfg.ChallengePrompt = defaultHighRiskChallengePrompt
	}
	if strings.TrimSpace(cfg.Scope) == "" {
		cfg.Scope = "user"
	}
	return cfg
}

func HashPassword(plain string) (string, error) {
	if plain == "" {
		return "", fmt.Errorf("password must not be empty")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	const (
		memory      = 64 * 1024
		iterations  = 3
		parallelism = 4
		keyLen      = 32
	)
	hash := argon2.IDKey([]byte(plain), salt, memory, iterations, parallelism, keyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memory,
		iterations,
		parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func VerifyPassword(hashValue, plain string) bool {
	if strings.TrimSpace(hashValue) == "" || plain == "" {
		return false
	}
	parts := strings.Split(hashValue, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != 19 {
		return false
	}
	var memory, iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	computed := argon2.IDKey([]byte(plain), salt, memory, iterations, parallelism, uint32(len(decodedHash)))
	return subtle.ConstantTimeCompare(decodedHash, computed) == 1
}

func (e *Engine) SetHighRiskAuthConfig(cfg HighRiskAuthConfig) {
	cfg = normalizeHighRiskAuthConfig(cfg)
	e.highRiskMu.Lock()
	defer e.highRiskMu.Unlock()
	e.highRiskAuth = cfg
	if e.highRiskStates == nil {
		e.highRiskStates = make(map[string]*highRiskUserState)
	}
	if !cfg.Enabled {
		e.highRiskStates = make(map[string]*highRiskUserState)
	}
}

func (e *Engine) handleHighRiskPasswordReply(p Platform, msg *Message, content string) bool {
	cfg, state, ok := e.highRiskStateForAuth(msg.UserID)
	if !ok || !looksLikeHighRiskPasswordReply(msg, content) {
		return false
	}

	now := time.Now()
	e.highRiskMu.Lock()
	defer e.highRiskMu.Unlock()

	state = e.getHighRiskUserStateLocked(msg.UserID)
	if state.Pending == nil {
		return false
	}
	if state.Pending.CreatedAt.Add(time.Duration(cfg.PendingTTLSecs) * time.Second).Before(now) {
		slog.Info("high_risk.pending_expired",
			"project", e.name,
			"user_id", msg.UserID,
			"platform", msg.Platform,
			"summary", state.Pending.Summary,
		)
		state.Pending = nil
		e.reply(p, msg.ReplyCtx, "高风险授权请求已过期，请重新发起原操作。")
		return true
	}
	if !VerifyPassword(cfg.PasswordHash, content) {
		state.Pending.FailureCount++
		slog.Info("high_risk.verify_failure",
			"project", e.name,
			"user_id", msg.UserID,
			"platform", msg.Platform,
			"failure_count", state.Pending.FailureCount,
			"summary", state.Pending.Summary,
		)
		if state.Pending.FailureCount >= cfg.MaxFailures {
			state.Pending = nil
			e.reply(p, msg.ReplyCtx, "密码错误，高风险授权已失效，请重新发起原操作。")
			return true
		}
		e.reply(p, msg.ReplyCtx, "密码错误，本次高风险操作未执行")
		return true
	}

	pending := state.Pending
	state.UnlockedUntil = now.Add(time.Duration(cfg.UnlockWindowSecs) * time.Second)
	state.Pending = nil
	slog.Info("high_risk.verify_success",
		"project", e.name,
		"user_id", msg.UserID,
		"platform", msg.Platform,
		"summary", pending.Summary,
		"unlock_window_secs", cfg.UnlockWindowSecs,
	)
	slog.Info("high_risk.pending_replayed",
		"project", e.name,
		"user_id", msg.UserID,
		"platform", msg.Platform,
		"summary", pending.Summary,
	)

	replay := pending.Message
	replay.ReplyCtx = msg.ReplyCtx
	replay.MessageID = ""
	go e.handleMessage(p, &replay)
	return true
}

func (e *Engine) handleHighRiskNaturalLanguage(p Platform, msg *Message, content string, agent Agent) bool {
	cfg, unlocked := e.highRiskStatus(msg.UserID)
	if !cfg.Enabled || unlocked {
		return false
	}
	workDir := e.commandWorkDir(agent, msg)
	if !isHighRiskNaturalLanguage(content, workDir, e.highRiskSafeRoots(workDir)) {
		return false
	}
	e.issueHighRiskChallenge(p, msg, cfg, content)
	return true
}

func (e *Engine) maybeBlockHighRiskCommand(p Platform, msg *Message, raw string) bool {
	cfg, unlocked := e.highRiskStatus(msg.UserID)
	if !cfg.Enabled || unlocked {
		return false
	}
	if !e.isHighRiskCommand(msg, raw) {
		return false
	}
	e.issueHighRiskChallenge(p, msg, cfg, raw)
	return true
}

func (e *Engine) issueHighRiskChallenge(p Platform, msg *Message, cfg HighRiskAuthConfig, raw string) {
	summary := summarizeHighRiskRequest(raw)

	e.highRiskMu.Lock()
	state := e.getHighRiskUserStateLocked(msg.UserID)
	state.Pending = &highRiskPendingRequest{
		Message:   cloneMessage(msg),
		CreatedAt: time.Now(),
		Summary:   summary,
	}
	e.highRiskMu.Unlock()

	slog.Info("high_risk.challenge_issued",
		"project", e.name,
		"user_id", msg.UserID,
		"platform", msg.Platform,
		"summary", summary,
	)
	e.reply(p, msg.ReplyCtx, cfg.ChallengePrompt)
}

func (e *Engine) highRiskStatus(userID string) (HighRiskAuthConfig, bool) {
	e.highRiskMu.Lock()
	defer e.highRiskMu.Unlock()
	cfg := e.highRiskAuth
	if !cfg.Enabled {
		return cfg, false
	}
	state := e.getHighRiskUserStateLocked(userID)
	now := time.Now()
	if state.Pending != nil && state.Pending.CreatedAt.Add(time.Duration(cfg.PendingTTLSecs)*time.Second).Before(now) {
		slog.Info("high_risk.pending_expired",
			"project", e.name,
			"user_id", userID,
			"summary", state.Pending.Summary,
		)
		state.Pending = nil
	}
	if !state.UnlockedUntil.IsZero() && now.After(state.UnlockedUntil) {
		state.UnlockedUntil = time.Time{}
	}
	return cfg, now.Before(state.UnlockedUntil)
}

func (e *Engine) highRiskStateForAuth(userID string) (HighRiskAuthConfig, *highRiskUserState, bool) {
	e.highRiskMu.Lock()
	defer e.highRiskMu.Unlock()
	cfg := e.highRiskAuth
	if !cfg.Enabled {
		return cfg, nil, false
	}
	return cfg, e.getHighRiskUserStateLocked(userID), true
}

func (e *Engine) getHighRiskUserStateLocked(userID string) *highRiskUserState {
	if e.highRiskStates == nil {
		e.highRiskStates = make(map[string]*highRiskUserState)
	}
	state := e.highRiskStates[userID]
	if state == nil {
		state = &highRiskUserState{}
		e.highRiskStates[userID] = state
	}
	return state
}

func (e *Engine) isHighRiskCommand(msg *Message, raw string) bool {
	parts := strings.Fields(strings.TrimSpace(raw))
	if len(parts) == 0 {
		return false
	}
	cmdID := matchPrefix(strings.ToLower(strings.TrimPrefix(parts[0], "/")), builtinCommands)
	args := parts[1:]

	switch cmdID {
	case "shell", "restart", "upgrade":
		return true
	case "commands":
		return len(args) > 0 && strings.EqualFold(args[0], "addexec")
	case "show":
		target := strings.TrimSpace(strings.Join(args, " "))
		return isProtectedHostPath(e.resolveHighRiskPath(msg, target))
	case "dir":
		target := strings.TrimSpace(strings.Join(args, " "))
		if target == "" {
			return false
		}
		lower := strings.ToLower(target)
		if lower == "help" || lower == "-h" || lower == "--help" || lower == "reset" {
			return false
		}
		resolved := e.resolveHighRiskPath(msg, target)
		if isProtectedHostPath(resolved) {
			return true
		}
		return !pathWithinAnyRoot(resolved, e.highRiskSafeRoots(e.commandWorkDirForRisk(msg)))
	}
	return false
}

func (e *Engine) highRiskSafeRoots(currentWorkDir string) []string {
	var roots []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		roots = append(roots, normalizeSlashPath(v))
	}
	add(e.baseWorkDir)
	add(currentWorkDir)
	if e.multiWorkspace {
		add(e.baseDir)
	}
	return roots
}

func (e *Engine) resolveHighRiskPath(msg *Message, target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if strings.HasPrefix(target, "~") {
		if homeDir, err := os.UserHomeDir(); err == nil {
			target = filepath.Join(homeDir, strings.TrimPrefix(target, "~"))
		}
	}
	if strings.HasPrefix(strings.ReplaceAll(target, "\\", "/"), "/") {
		return normalizeSlashPath(target)
	}
	baseDir := e.commandWorkDirForRisk(msg)
	if baseDir == "" {
		baseDir, _ = os.Getwd()
	}
	resolved := target
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(baseDir, resolved)
	}
	if abs, err := filepath.Abs(resolved); err == nil {
		resolved = abs
	}
	return normalizeSlashPath(resolved)
}

func (e *Engine) commandWorkDirForRisk(msg *Message) string {
	agent, err := e.resolveCommandWorkDirAgent(msg)
	if err == nil {
		return e.commandWorkDir(agent, msg)
	}
	return e.baseWorkDir
}

func (e *Engine) resolveCommandWorkDirAgent(msg *Message) (Agent, error) {
	if !e.multiWorkspace {
		return e.agent, nil
	}
	channelID := effectiveChannelID(msg)
	workspace, _, err := e.resolveWorkspace(dummyPlatform(msg.Platform), channelID)
	if err != nil || workspace == "" {
		return e.agent, err
	}
	agent, _, _, _, err := e.workspaceContext(workspace, msg.SessionKey)
	return agent, err
}

func isHighRiskNaturalLanguage(content string, currentWorkDir string, safeRoots []string) bool {
	normalized := strings.ToLower(strings.TrimSpace(content))
	if normalized == "" {
		return false
	}
	if containsProtectedPathMention(normalized) && containsAny(normalized,
		"查看", "看", "读取", "显示", "read", "show", "cat",
		"修改", "更改", "替换", "删除", "重置", "编辑", "写入", "覆盖",
		"edit", "update", "change", "delete", "remove", "reset", "write", "replace",
	) {
		return true
	}
	if containsAny(normalized,
		"systemctl", "nginx", "反代", "防火墙", "ufw", "ssh", "cron", "定时任务",
		"restart service", "restart the service", "restart server", "reboot", "shutdown",
		"主机重启", "关机", "重启服务", "停止服务", "启动服务", "systemd",
	) {
		return true
	}
	if containsAny(normalized, "token", "secret", "password", "api key", "凭据", "认证", "密钥") &&
		containsAny(normalized, "查看", "读取", "轮换", "更换", "修改", "read", "show", "rotate", "change", "replace") {
		return true
	}
	for _, candidate := range extractPathCandidates(content, currentWorkDir) {
		if isProtectedHostPath(candidate) {
			return true
		}
		if !pathWithinAnyRoot(candidate, safeRoots) &&
			containsAny(normalized, "查看", "读取", "修改", "删除", "重置", "read", "show", "edit", "delete", "reset", "change", "write") {
			return true
		}
	}
	return false
}

func looksLikeHighRiskPasswordReply(msg *Message, content string) bool {
	if msg.Audio != nil || msg.Location != nil || len(msg.Images) > 0 || len(msg.Files) > 0 {
		return false
	}
	content = strings.TrimSpace(content)
	if content == "" || strings.HasPrefix(content, "/") || strings.HasPrefix(content, "!") {
		return false
	}
	return !strings.ContainsAny(content, "\r\n")
}

func containsProtectedPathMention(content string) bool {
	for _, prefix := range []string{
		"/etc", "/home/frog/.ssh", "/home/frog/.codex", "/home/frog/.config/systemd",
		"/srv/projects/", "/var/spool/cron", "/etc/cron", "/etc/nginx", "/etc/ufw",
	} {
		if strings.Contains(content, prefix) {
			return true
		}
	}
	return false
}

func extractPathCandidates(content string, currentWorkDir string) []string {
	fields := strings.FieldsFunc(content, func(r rune) bool {
		switch r {
		case ' ', '\n', '\r', '\t', ',', '，', '。', ':', '：', ';', '；', '(', ')', '（', '）', '"', '\'':
			return true
		default:
			return false
		}
	})
	var out []string
	for _, field := range fields {
		if strings.Contains(field, "/") || strings.HasPrefix(field, "~") {
			if strings.HasPrefix(strings.ReplaceAll(field, "\\", "/"), "/") || strings.HasPrefix(field, "~") {
				out = append(out, normalizeSlashPath(field))
				continue
			}
			resolved := field
			if currentWorkDir != "" {
				resolved = filepath.Join(currentWorkDir, field)
			}
			out = append(out, normalizeSlashPath(resolved))
		}
	}
	return out
}

func isProtectedHostPath(target string) bool {
	target = normalizeSlashPath(target)
	if target == "" {
		return false
	}
	for _, prefix := range []string{
		"/etc",
		"/home/frog/.ssh",
		"/home/frog/.codex",
		"/home/frog/.config/systemd",
		"/var/spool/cron",
		"/etc/cron",
		"/etc/nginx",
		"/etc/ufw",
	} {
		if pathWithinRoot(target, prefix) {
			return true
		}
	}
	return highRiskProtectedProjectStackRe.MatchString(target)
}

func pathWithinAnyRoot(target string, roots []string) bool {
	for _, root := range roots {
		if pathWithinRoot(target, root) {
			return true
		}
	}
	return false
}

func pathWithinRoot(target, root string) bool {
	target = normalizeSlashPath(target)
	root = normalizeSlashPath(root)
	if target == "" || root == "" {
		return false
	}
	if runtime.GOOS == "windows" || strings.Contains(target, ":") || strings.Contains(root, ":") {
		target = strings.ToLower(target)
		root = strings.ToLower(root)
	}
	return target == root || strings.HasPrefix(target, root+"/")
}

func normalizeSlashPath(v string) string {
	v = strings.ReplaceAll(strings.TrimSpace(v), "\\", "/")
	if v == "" {
		return ""
	}
	return path.Clean(v)
}

func containsAny(content string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(content, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func summarizeHighRiskRequest(raw string) string {
	summary := strings.TrimSpace(raw)
	if summary == "" {
		return "<empty>"
	}
	summary = highRiskSensitiveValueRe.ReplaceAllString(summary, "$1=<redacted>")
	for _, prefix := range []string{
		"/etc/nginx", "/etc/ufw", "/etc", "/home/frog/.ssh", "/home/frog/.codex",
		"/home/frog/.config/systemd", "/srv/projects/", "/var/spool/cron", "/etc/cron",
	} {
		summary = strings.ReplaceAll(summary, prefix, "<protected-path>")
	}
	if len([]rune(summary)) > 120 {
		summary = string([]rune(summary)[:120]) + "..."
	}
	return summary
}

func cloneMessage(msg *Message) Message {
	if msg == nil {
		return Message{}
	}
	cp := *msg
	if len(msg.Images) > 0 {
		cp.Images = append([]ImageAttachment(nil), msg.Images...)
	}
	if len(msg.Files) > 0 {
		cp.Files = append([]FileAttachment(nil), msg.Files...)
	}
	if msg.Audio != nil {
		audio := *msg.Audio
		cp.Audio = &audio
	}
	if msg.Location != nil {
		loc := *msg.Location
		cp.Location = &loc
	}
	return cp
}

type noOpPlatform struct{ name string }

func (p noOpPlatform) Name() string                             { return p.name }
func (p noOpPlatform) Start(MessageHandler) error               { return nil }
func (p noOpPlatform) Reply(context.Context, any, string) error { return nil }
func (p noOpPlatform) Send(context.Context, any, string) error  { return nil }
func (p noOpPlatform) Stop() error                              { return nil }

func dummyPlatform(name string) Platform {
	return noOpPlatform{name: name}
}
