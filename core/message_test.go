package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSanitizeAttachmentFileName covers the basename-stripping rules used by
// SaveFilesToDisk to reject path-traversal in user-supplied filenames.
func TestSanitizeAttachmentFileName(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"image.png", "image.png"},
		{"subdir/file.txt", "file.txt"},
		{"../../escape.txt", "escape.txt"},
		{"/etc/passwd", "passwd"},
		// Windows-style separators get normalized so Linux strips them too.
		{`..\..\windows-escape.txt`, "windows-escape.txt"},
		{`C:\Users\foo\bar.exe`, "bar.exe"},
		// Anything that would still join to a parent / current directory is
		// returned as "" so the caller falls back to a generated name.
		{"..", ""},
		{".", ""},
		{"", ""},
		{"../", ""},
		{`..\`, ""},
		{"./../foo", "foo"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := sanitizeAttachmentFileName(tt.in)
			if got != tt.want {
				t.Errorf("sanitizeAttachmentFileName(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestSaveFilesToDisk_RejectsPathTraversal is a regression test for a real
// path-traversal vulnerability in SaveFilesToDisk: the attachment FileName
// (which comes from user-controlled IM/HTTP upload metadata) was passed
// directly to filepath.Join, so an attacker uploading a file named
// "../../escape.txt" wrote outside the intended attachments directory into
// the agent's workDir / above. The fix sanitizes FileName to a basename;
// this test asserts every file lands inside attachDir, with no escapees.
func TestSaveFilesToDisk_RejectsPathTraversal(t *testing.T) {
	workDir := t.TempDir()
	attachDir := filepath.Join(workDir, "artifacts", "incoming", "files")

	files := []FileAttachment{
		// The original repro: walks two levels up out of attachments and
		// out of .cc-connect/, landing directly in workDir.
		{FileName: "../../escape.txt", Data: []byte("payload")},
		// Three levels up — would land in workDir's parent without the fix.
		{FileName: "../../../way-up.txt", Data: []byte("payload")},
		// Windows-style separators must also be stripped on Linux so a
		// cross-platform attacker can't bypass the basename guard.
		{FileName: `..\..\winescape.txt`, Data: []byte("payload")},
		// Subdirectory in the name — file should land in attachDir, not in
		// a created subdir, since we strip directory components.
		{FileName: "subdir/inner.txt", Data: []byte("payload")},
		// Plain name should still work normally.
		{FileName: "ok.txt", Data: []byte("payload")},
		// A name that sanitizes to empty should fall back to a generated
		// name in attachDir, not crash and not escape.
		{FileName: "..", Data: []byte("payload")},
	}

	paths := SaveFilesToDisk(workDir, files)

	// Every returned path must live inside attachDir.
	for _, p := range paths {
		if !strings.HasPrefix(p, attachDir+string(filepath.Separator)) {
			t.Errorf("SaveFilesToDisk wrote outside attachments dir: %q (attachDir=%q)", p, attachDir)
		}
	}

	// Walk the workDir tree and confirm no file landed above attachDir.
	if err := filepath.Walk(workDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasPrefix(path, attachDir+string(filepath.Separator)) {
			t.Errorf("found stray attachment outside attachments dir: %q", path)
		}
		return nil
	}); err != nil {
		t.Fatalf("walk: %v", err)
	}

	// Sanity: at minimum the legitimate "ok.txt" must have been written.
	okPath := filepath.Join(attachDir, "ok.txt")
	if _, err := os.Stat(okPath); err != nil {
		t.Errorf("legitimate ok.txt not saved: %v", err)
	}
}

func TestSaveImagesToDisk_WritesIntoIncomingArtifacts(t *testing.T) {
	workDir := t.TempDir()
	imageDir := filepath.Join(workDir, "artifacts", "incoming", "images")

	paths := SaveImagesToDisk(workDir, []ImageAttachment{
		{MimeType: "image/png", Data: []byte("png")},
		{MimeType: "image/jpeg", Data: []byte("jpg")},
	})

	if len(paths) != 2 {
		t.Fatalf("SaveImagesToDisk paths len = %d, want 2", len(paths))
	}
	for _, p := range paths {
		if !strings.HasPrefix(p, imageDir+string(filepath.Separator)) {
			t.Fatalf("SaveImagesToDisk wrote outside image dir: %q", p)
		}
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected staged image to exist: %v", err)
		}
	}
}

func TestSaveFilesToSessionDir_WritesIntoSessionArtifacts(t *testing.T) {
	workDir := t.TempDir()
	sessionDir := "s12__报销单据核对"
	attachDir := filepath.Join(workDir, "artifacts", "sessions", sessionDir)

	paths := SaveFilesToSessionDir(workDir, sessionDir, []FileAttachment{
		{FileName: "销售数据.xlsx", Data: []byte("sheet-a")},
		{FileName: "对账单.xlsx", Data: []byte("sheet-b")},
	})

	if len(paths) != 2 {
		t.Fatalf("SaveFilesToSessionDir paths len = %d, want 2", len(paths))
	}
	for _, p := range paths {
		if !strings.HasPrefix(p, attachDir+string(filepath.Separator)) {
			t.Fatalf("SaveFilesToSessionDir wrote outside session dir: %q", p)
		}
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected staged file to exist: %v", err)
		}
	}
}

func TestSaveImagesToSessionDir_WritesIntoSessionArtifacts(t *testing.T) {
	workDir := t.TempDir()
	sessionDir := "s12__报销单据核对"
	imageDir := filepath.Join(workDir, "artifacts", "sessions", sessionDir)

	paths := SaveImagesToSessionDir(workDir, sessionDir, []ImageAttachment{
		{MimeType: "image/png", Data: []byte("png")},
		{MimeType: "image/jpeg", Data: []byte("jpg")},
	})

	if len(paths) != 2 {
		t.Fatalf("SaveImagesToSessionDir paths len = %d, want 2", len(paths))
	}
	for _, p := range paths {
		if !strings.HasPrefix(p, imageDir+string(filepath.Separator)) {
			t.Fatalf("SaveImagesToSessionDir wrote outside session dir: %q", p)
		}
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected staged image to exist: %v", err)
		}
	}
}

func TestSaveImagesToDisk_ReusesExistingAbsolutePath(t *testing.T) {
	workDir := t.TempDir()
	preStaged := filepath.Join(workDir, "artifacts", "sessions", "s12__报销单据核对", "IMG_报销单_01.png")
	if err := os.MkdirAll(filepath.Dir(preStaged), 0o755); err != nil {
		t.Fatalf("mkdir pre-staged dir: %v", err)
	}
	if err := os.WriteFile(preStaged, []byte("png"), 0o644); err != nil {
		t.Fatalf("write pre-staged image: %v", err)
	}

	paths := SaveImagesToDisk(workDir, []ImageAttachment{{
		MimeType: "image/png",
		FileName: preStaged,
	}})

	if len(paths) != 1 {
		t.Fatalf("SaveImagesToDisk paths len = %d, want 1", len(paths))
	}
	if paths[0] != preStaged {
		t.Fatalf("SaveImagesToDisk reused path = %q, want %q", paths[0], preStaged)
	}
	incomingDir := filepath.Join(workDir, "artifacts", "incoming", "images")
	if _, err := os.Stat(incomingDir); !os.IsNotExist(err) {
		t.Fatalf("incoming image dir should not be created when reusing staged path, stat err=%v", err)
	}
}

func TestSaveFilesToDisk_ReusesExistingAbsolutePath(t *testing.T) {
	workDir := t.TempDir()
	preStaged := filepath.Join(workDir, "artifacts", "sessions", "s12__报销单据核对", "销售数据.xlsx")
	if err := os.MkdirAll(filepath.Dir(preStaged), 0o755); err != nil {
		t.Fatalf("mkdir pre-staged dir: %v", err)
	}
	if err := os.WriteFile(preStaged, []byte("sheet"), 0o644); err != nil {
		t.Fatalf("write pre-staged file: %v", err)
	}

	paths := SaveFilesToDisk(workDir, []FileAttachment{{
		MimeType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		FileName: preStaged,
	}})

	if len(paths) != 1 {
		t.Fatalf("SaveFilesToDisk paths len = %d, want 1", len(paths))
	}
	if paths[0] != preStaged {
		t.Fatalf("SaveFilesToDisk reused path = %q, want %q", paths[0], preStaged)
	}
	incomingDir := filepath.Join(workDir, "artifacts", "incoming", "files")
	if _, err := os.Stat(incomingDir); !os.IsNotExist(err) {
		t.Fatalf("incoming file dir should not be created when reusing staged path, stat err=%v", err)
	}
}
