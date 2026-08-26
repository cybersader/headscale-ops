package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestConfigureWritesHiddenOwnerOnlyCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config", "config.json")
	secretBytes := []byte("bootstrap-api-key")
	dependencies := commandDependencies{
		readSecret: func() ([]byte, error) { return secretBytes, nil },
		now:        time.Now,
	}
	var stdout, stderr bytes.Buffer
	code := runCLIWithDependencies([]string{"--config", path, "configure", "--server-url", "https://headscale.home:30210/"}, &stdout, &stderr, dependencies)
	if code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), "bootstrap-api-key") {
		t.Fatal("configure output exposed API key")
	}
	for _, value := range secretBytes {
		if value != 0 {
			t.Fatal("configure did not zero injected secret bytes")
		}
	}
	config, err := readConfig(path)
	if err != nil {
		t.Fatalf("readConfig() error = %v", err)
	}
	if config.ServerURL != "https://headscale.home:30210" || config.APIKey != "bootstrap-api-key" {
		t.Fatalf("config = %#v", config)
	}
}

func TestPreAuthCreateWritesOnlySecretToStdout(t *testing.T) {
	path := writeTestConfig(t)
	_, client := newTLSTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/preauthkey" {
			http.NotFound(w, r)
			return
		}
		writeJSON(t, w, map[string]any{"preAuthKey": map[string]any{"id": "11", "key": "hskey-auth-created-secret"}})
	}))
	dependencies := commandDependencies{
		now: func() time.Time { return time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC) },
		newClient: func(Config) (*Client, error) {
			return client, nil
		},
	}
	var stdout, stderr bytes.Buffer
	code := runCLIWithDependencies([]string{"--config", path, "preauth", "create", "--user", "7", "--expiration", "24h", "--tag", "tag:test"}, &stdout, &stderr, dependencies)
	if code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if stdout.String() != "hskey-auth-created-secret\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if strings.Contains(stderr.String(), "hskey-auth-created-secret") || !strings.Contains(stderr.String(), "id=11") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestPreAuthListOmitsStoredSecrets(t *testing.T) {
	path := writeTestConfig(t)
	_, client := newTLSTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{"preAuthKeys": []map[string]any{{
			"id": "11", "key": "must-not-be-listed", "user": map[string]any{"name": "alice"}, "expiration": "2026-08-22T00:00:00Z",
		}}})
	}))
	dependencies := commandDependencies{newClient: func(Config) (*Client, error) { return client, nil }}
	var stdout, stderr bytes.Buffer
	code := runCLIWithDependencies([]string{"--config", path, "preauth", "list"}, &stdout, &stderr, dependencies)
	if code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), "must-not-be-listed") {
		t.Fatal("preauth list exposed key material")
	}
	if !strings.Contains(stdout.String(), "alice") || !strings.Contains(stdout.String(), "11") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestDestructiveCommandsRequireExplicitYes(t *testing.T) {
	path := writeTestConfig(t)
	var hits atomic.Int32
	_, client := newTLSTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		writeJSON(t, w, map[string]any{})
	}))
	dependencies := commandDependencies{newClient: func(Config) (*Client, error) { return client, nil }}
	for _, args := range [][]string{
		{"--config", path, "user", "delete", "--id", "7"},
		{"--config", path, "node", "delete", "--id", "9"},
		{"--config", path, "node", "expire", "--id", "9"},
		{"--config", path, "node", "set-tags", "--id", "9", "--tag", "tag:server"},
		{"--config", path, "node", "set-tags", "--id", "9", "--clear", "--yes"},
		{"--config", path, "preauth", "expire", "--id", "11"},
		{"--config", path, "apikey", "expire", "--id", "13"},
	} {
		var stdout, stderr bytes.Buffer
		if code := runCLIWithDependencies(args, &stdout, &stderr, dependencies); code != 2 {
			t.Fatalf("args=%v exit=%d stdout=%q stderr=%q", args, code, stdout.String(), stderr.String())
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("destructive command contacted server without --yes: hits=%d", hits.Load())
	}
}

func TestSafeTextNeutralizesTerminalControls(t *testing.T) {
	got := safeText("normal\x1b[31m\nforged\tcell")
	if strings.ContainsAny(got, "\x1b\n\t") {
		t.Fatalf("safeText() = %q", got)
	}
	if !strings.Contains(got, "normal?[31m?forged?cell") {
		t.Fatalf("safeText() = %q", got)
	}
}

func TestExpirationValidation(t *testing.T) {
	now := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
	if got, err := parseExpiration("24h", now); err != nil || !got.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("duration expiration = %v, %v", got, err)
	}
	for _, raw := range []string{"0s", "-1h", "now", "not-a-time", "2026-08-20T00:00:00Z"} {
		if _, err := parseExpiration(raw, now); err == nil {
			t.Fatalf("parseExpiration(%q) accepted invalid value", raw)
		}
	}
}

func TestConfigFlagMayAppearBeforeOrAfterCommand(t *testing.T) {
	for _, args := range [][]string{
		{"--config", "/tmp/config", "status"},
		{"status", "--config=/tmp/config"},
		{"status", "--config", "/tmp/config"},
	} {
		path, remaining, err := extractConfigPath(args)
		if err != nil || path != "/tmp/config" || len(remaining) != 1 || remaining[0] != "status" {
			t.Fatalf("extractConfigPath(%v) = %q, %v, %v", args, path, remaining, err)
		}
	}
}

func TestWriteSecretRejectsUnsafeServerValues(t *testing.T) {
	for _, value := range []string{"", "secret\nforged", "secret\x1b[31m"} {
		if err := writeSecret(io.Discard, value); err == nil {
			t.Fatalf("writeSecret(%q) accepted unsafe value", value)
		}
	}
}

func TestStatusRequiresSupportedUnmodifiedHeadscale(t *testing.T) {
	for _, test := range []struct {
		name      string
		version   string
		dirty     bool
		wantCode  int
		wantError string
	}{
		{name: "tagged version", version: "v0.29.3", wantCode: 0},
		{name: "bare version", version: "0.29.3", wantCode: 0},
		{name: "unsupported version", version: "v0.30.0", wantCode: 1, wantError: "unsupported Headscale version"},
		{name: "dirty build", version: "v0.29.3", dirty: true, wantCode: 1, wantError: "dirty build"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeTestConfig(t)
			_, client := newTLSTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/health":
					writeJSON(t, w, map[string]any{"status": "pass"})
				case "/version":
					writeJSON(t, w, map[string]any{
						"version": test.version,
						"commit":  "5aff68b",
						"go":      map[string]any{"version": "go1.24.4", "os": "linux", "arch": "amd64"},
						"dirty":   test.dirty,
					})
				case "/api/v1/health":
					writeJSON(t, w, map[string]any{"databaseConnectivity": true})
				default:
					http.NotFound(w, r)
				}
			}))
			dependencies := commandDependencies{newClient: func(Config) (*Client, error) { return client, nil }}
			var stdout, stderr bytes.Buffer
			code := runCLIWithDependencies([]string{"--config", path, "status"}, &stdout, &stderr, dependencies)
			if code != test.wantCode {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if test.wantError != "" && !strings.Contains(stderr.String(), test.wantError) {
				t.Fatalf("stderr = %q, want %q", stderr.String(), test.wantError)
			}
		})
	}
}

func TestUserCreateNormalizesOptionalFields(t *testing.T) {
	path := writeTestConfig(t)
	_, client := newTLSTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := decodeJSONMap(t, r)
		for field, want := range map[string]string{
			"name": "alice", "displayName": "Alice Example", "email": "alice@example.com", "pictureUrl": "https://example.com/alice.png",
		} {
			if got := body[field]; got != want {
				t.Errorf("%s = %#v, want %q", field, got, want)
			}
		}
		writeJSON(t, w, map[string]any{"user": map[string]any{"id": "7", "name": "alice"}})
	}))
	dependencies := commandDependencies{newClient: func(Config) (*Client, error) { return client, nil }}
	var stdout, stderr bytes.Buffer
	code := runCLIWithDependencies([]string{
		"--config", path, "user", "create", "--name", " alice ", "--display-name", " Alice Example ",
		"--email", " alice@example.com ", "--picture-url", " https://example.com/alice.png ",
	}, &stdout, &stderr, dependencies)
	if code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestNodeRenameReportsAssignedGivenName(t *testing.T) {
	path := writeTestConfig(t)
	_, client := newTLSTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{"node": map[string]any{
			"id": "9", "name": "client-hostname", "givenName": "workstation",
		}})
	}))
	dependencies := commandDependencies{newClient: func(Config) (*Client, error) { return client, nil }}
	var stdout, stderr bytes.Buffer
	code := runCLIWithDependencies([]string{"--config", path, "node", "rename", "--id", "9", "--name", "workstation"}, &stdout, &stderr, dependencies)
	if code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "name=workstation") || strings.Contains(stdout.String(), "client-hostname") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestNodeExpireNowUsesServerClock(t *testing.T) {
	path := writeTestConfig(t)
	_, client := newTLSTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			t.Errorf("immediate expiry query = %q, want empty", r.URL.RawQuery)
		}
		writeJSON(t, w, map[string]any{"node": map[string]any{"id": "9", "expiry": "2026-08-21T12:00:00Z"}})
	}))
	dependencies := commandDependencies{
		now:       func() time.Time { return time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC) },
		newClient: func(Config) (*Client, error) { return client, nil },
	}
	var stdout, stderr bytes.Buffer
	code := runCLIWithDependencies([]string{"--config", path, "node", "expire", "--id", "9", "--yes"}, &stdout, &stderr, dependencies)
	if code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestNodeSetTagsRequiresConfirmationAndSendsTags(t *testing.T) {
	path := writeTestConfig(t)
	_, client := newTLSTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := decodeJSONMap(t, r)
		tags, ok := body["tags"].([]any)
		if !ok || len(tags) != 1 || tags[0] != "tag:server" {
			t.Errorf("tags body = %#v", body)
		}
		writeJSON(t, w, map[string]any{"node": map[string]any{"id": "9", "tags": []string{"tag:server"}}})
	}))
	dependencies := commandDependencies{newClient: func(Config) (*Client, error) { return client, nil }}
	var stdout, stderr bytes.Buffer
	code := runCLIWithDependencies([]string{"--config", path, "node", "set-tags", "--id", "9", "--tag", "tag:server", "--yes"}, &stdout, &stderr, dependencies)
	if code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestSecretOutputFailuresExpireCreatedCredentials(t *testing.T) {
	t.Run("pre-auth key", func(t *testing.T) {
		path := writeTestConfig(t)
		var expired atomic.Bool
		_, client := newTLSTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v1/preauthkey":
				writeJSON(t, w, map[string]any{"preAuthKey": map[string]any{"id": "11", "key": "hskey-auth-created-secret"}})
			case "/api/v1/preauthkey/expire":
				if body := decodeJSONMap(t, r); body["id"] != "11" {
					t.Errorf("expire body = %#v", body)
				}
				expired.Store(true)
				writeJSON(t, w, map[string]any{})
			default:
				http.NotFound(w, r)
			}
		}))
		dependencies := commandDependencies{
			now:       func() time.Time { return time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC) },
			newClient: func(Config) (*Client, error) { return client, nil },
		}
		var stderr bytes.Buffer
		code := runCLIWithDependencies([]string{"--config", path, "preauth", "create", "--user", "7", "--expiration", "1h"}, errorWriter{}, &stderr, dependencies)
		if code != 1 || !expired.Load() {
			t.Fatalf("exit=%d expired=%t stderr=%q", code, expired.Load(), stderr.String())
		}
		if strings.Contains(stderr.String(), "hskey-auth-created-secret") || !strings.Contains(stderr.String(), "expired automatically") {
			t.Fatalf("stderr = %q", stderr.String())
		}
	})

	t.Run("API key", func(t *testing.T) {
		path := writeTestConfig(t)
		var expired atomic.Bool
		_, client := newTLSTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v1/apikey":
				writeJSON(t, w, map[string]any{"apiKey": "hskey-api-AbCdEfGhIjKl-created-secret"})
			case "/api/v1/apikey/expire":
				if body := decodeJSONMap(t, r); body["prefix"] != "hskey-api-AbCdEfGhIjKl" {
					t.Errorf("expire body = %#v", body)
				}
				expired.Store(true)
				writeJSON(t, w, map[string]any{})
			default:
				http.NotFound(w, r)
			}
		}))
		dependencies := commandDependencies{
			now:       func() time.Time { return time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC) },
			newClient: func(Config) (*Client, error) { return client, nil },
		}
		var stderr bytes.Buffer
		code := runCLIWithDependencies([]string{"--config", path, "apikey", "create", "--expiration", "1h"}, errorWriter{}, &stderr, dependencies)
		if code != 1 || !expired.Load() {
			t.Fatalf("exit=%d expired=%t stderr=%q", code, expired.Load(), stderr.String())
		}
		if strings.Contains(stderr.String(), "created-secret") || !strings.Contains(stderr.String(), "expired automatically") {
			t.Fatalf("stderr = %q", stderr.String())
		}
	})
}

func TestUserListSortsNumericIDs(t *testing.T) {
	path := writeTestConfig(t)
	_, client := newTLSTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{"users": []map[string]any{
			{"id": "11", "name": "eleven"}, {"id": "2", "name": "two"}, {"id": "10", "name": "ten"},
		}})
	}))
	dependencies := commandDependencies{newClient: func(Config) (*Client, error) { return client, nil }}
	var stdout, stderr bytes.Buffer
	code := runCLIWithDependencies([]string{"--config", path, "user", "list"}, &stdout, &stderr, dependencies)
	if code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("stdout lines = %#v", lines)
	}
	for index, want := range []string{"2", "10", "11"} {
		fields := strings.Fields(lines[index+1])
		if len(fields) == 0 || fields[0] != want {
			t.Fatalf("line %d = %q, want ID %s", index+1, lines[index+1], want)
		}
	}
}

func TestTagValidationMatchesV0293(t *testing.T) {
	got, err := validateTags([]string{"tag:server", "tag:internal"})
	if err != nil || len(got) != 2 || got[0] != "tag:internal" || got[1] != "tag:server" {
		t.Fatalf("validateTags() = %#v, %v", got, err)
	}
	for _, values := range [][]string{
		{}, {"server"}, {"tag:"}, {"tag:Server"}, {"tag:server name"}, {"tag:server", "tag:server"},
	} {
		if _, err := validateTags(values); err == nil {
			t.Fatalf("validateTags(%q) accepted invalid values", values)
		}
	}
}

func TestAPIKeyPrefix(t *testing.T) {
	if got, err := apiKeyPrefix("hskey-api-AbCdEfGhIjKl-secret"); err != nil || got != "hskey-api-AbCdEfGhIjKl" {
		t.Fatalf("apiKeyPrefix() = %q, %v", got, err)
	}
	for _, value := range []string{"", "legacy.secret", "hskey-api-short-secret", "hskey-api-AbCdEfGhIj!l-secret"} {
		if _, err := apiKeyPrefix(value); err == nil {
			t.Fatalf("apiKeyPrefix(%q) accepted invalid value", value)
		}
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, errors.New("output failed")
}

func writeTestConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("{\"server_url\":\"https://headscale.home:30210\",\"api_key\":\"config-api-key\"}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func TestClientCanBeCalledWithCancelledContext(t *testing.T) {
	_, client := newTLSTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{"users": []any{}})
	}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.ListUsers(ctx); err == nil {
		t.Fatal("ListUsers() succeeded with cancelled context")
	}
}
