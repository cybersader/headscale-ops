package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeServerURLRequiresDirectHTTPSBase(t *testing.T) {
	valid := map[string]string{
		" https://headscale.home:30210/ ": "https://headscale.home:30210",
		"HTTPS://headscale.example.com":   "https://headscale.example.com",
	}
	for input, want := range valid {
		t.Run(input, func(t *testing.T) {
			got, err := normalizeServerURL(input)
			if err != nil {
				t.Fatalf("normalizeServerURL() error = %v", err)
			}
			if got != want {
				t.Fatalf("normalizeServerURL() = %q, want %q", got, want)
			}
		})
	}

	for _, input := range []string{
		"http://headscale.home:30210",
		"headscale.home:30210",
		"https://",
		"https://user:pass@headscale.home",
		"https://headscale.home/api/v1",
		"https://headscale.home?debug=1",
		"https://headscale.home#fragment",
		"https://headscale.home:",
	} {
		t.Run("reject "+input, func(t *testing.T) {
			if _, err := normalizeServerURL(input); err == nil {
				t.Fatalf("normalizeServerURL(%q) accepted invalid URL", input)
			}
		})
	}
}

func TestWriteAndReadConfigUseOwnerOnlyAtomicFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.json")
	config := Config{ServerURL: "https://headscale.home:30210/", APIKey: "secret-api-key"}
	if err := writeConfig(path, config); err != nil {
		t.Fatalf("writeConfig() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %04o, want 0600", info.Mode().Perm())
	}
	directoryInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("Stat(directory) error = %v", err)
	}
	if directoryInfo.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode = %04o, want 0700", directoryInfo.Mode().Perm())
	}

	got, err := readConfig(path)
	if err != nil {
		t.Fatalf("readConfig() error = %v", err)
	}
	if got.ServerURL != "https://headscale.home:30210" || got.APIKey != config.APIKey {
		t.Fatalf("readConfig() = %#v", got)
	}
}

func TestReadConfigRejectsUnsafeFiles(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.json")
	contents := []byte(`{"server_url":"https://headscale.home:30210","api_key":"secret"}`)
	if err := os.WriteFile(path, contents, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := readConfig(path); err == nil || !strings.Contains(err.Error(), "permissions 0644") {
		t.Fatalf("readConfig() error = %v", err)
	}

	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	link := filepath.Join(directory, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if _, err := readConfig(link); err == nil || !strings.Contains(err.Error(), "symbolic links") {
		t.Fatalf("readConfig(symlink) error = %v", err)
	}
}

func TestReadConfigRejectsUnknownOrTrailingJSON(t *testing.T) {
	for name, contents := range map[string]string{
		"unknown":  `{"server_url":"https://headscale.home","api_key":"secret","insecure":true}`,
		"trailing": `{"server_url":"https://headscale.home","api_key":"secret"}{}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			if _, err := readConfig(path); err == nil {
				t.Fatal("readConfig() accepted invalid JSON")
			}
		})
	}
}

func TestWriteConfigRejectsExistingSymlink(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("preserve"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	path := filepath.Join(directory, "config.json")
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	err := writeConfig(path, Config{ServerURL: "https://headscale.home", APIKey: "secret"})
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("writeConfig() error = %v", err)
	}
	contents, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(contents) != "preserve" {
		t.Fatalf("symlink target changed to %q", contents)
	}
}

func TestWriteConfigDoesNotChmodExistingSharedDirectory(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	path := filepath.Join(directory, "config.json")
	err := writeConfig(path, Config{ServerURL: "https://headscale.home", APIKey: "secret"})
	if err == nil || !strings.Contains(err.Error(), "config directory permissions 0755") {
		t.Fatalf("writeConfig() error = %v", err)
	}
	info, statErr := os.Stat(directory)
	if statErr != nil {
		t.Fatalf("Stat() error = %v", statErr)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("directory mode changed to %04o", info.Mode().Perm())
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("config file exists after refusal: %v", statErr)
	}
}

func TestReadConfigMissingFilePreservesNotExist(t *testing.T) {
	_, err := readConfig(filepath.Join(t.TempDir(), "missing.json"))
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("readConfig() error = %v", err)
	}
}
