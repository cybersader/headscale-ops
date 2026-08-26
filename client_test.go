package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTLSTestClient(t *testing.T, handler http.Handler) (*httptest.Server, *Client) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	client, err := NewClient(Config{ServerURL: server.URL, APIKey: "test-api-key"}, server.Client())
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	return server, client
}

func TestNewHTTPClientIsHardened(t *testing.T) {
	client := newHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("transport honors environment proxies")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLS config = %#v", transport.TLSClientConfig)
	}
	if transport.MaxResponseHeaderBytes != maxResponseHeaders {
		t.Fatalf("MaxResponseHeaderBytes = %d", transport.MaxResponseHeaderBytes)
	}
	if client.Timeout != requestTimeout {
		t.Fatalf("Timeout = %v", client.Timeout)
	}
	if client.CheckRedirect == nil || !errors.Is(client.CheckRedirect(&http.Request{}, nil), http.ErrUseLastResponse) {
		t.Fatal("redirect policy does not refuse redirects")
	}
}

func TestClientUsesV0293RESTShapes(t *testing.T) {
	var expireCalls atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || r.URL.Path == "/version" {
			if got := r.Header.Get("Authorization"); got != "" {
				t.Errorf("public endpoint %s Authorization = %q", r.URL.Path, got)
			}
			if r.URL.Path == "/health" {
				writeJSON(t, w, map[string]any{"status": "pass"})
			} else {
				writeJSON(t, w, map[string]any{
					"version": "v0.29.3", "commit": "5aff68b", "buildTime": "2026-08-01T00:00:00Z",
					"go": map[string]any{"version": "go1.24.4", "os": "linux", "arch": "amd64"}, "dirty": false,
				})
			}
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-api-key" {
			t.Errorf("%s Authorization = %q", r.URL.Path, got)
		}

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/health":
			writeJSON(t, w, map[string]any{"databaseConnectivity": true})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/user":
			writeJSON(t, w, map[string]any{"users": []map[string]any{{"id": "7", "name": "alice"}}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/user":
			body := decodeJSONMap(t, r)
			if body["name"] != "alice" {
				t.Errorf("create user body = %#v", body)
			}
			writeJSON(t, w, map[string]any{"user": map[string]any{"id": "7", "name": "alice"}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/user/7/rename/new name":
			if got := r.URL.EscapedPath(); got != "/api/v1/user/7/rename/new%20name" {
				t.Errorf("rename escaped path = %q", got)
			}
			writeJSON(t, w, map[string]any{"user": map[string]any{"id": "7", "name": "new name"}})
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/user/7":
			writeJSON(t, w, map[string]any{})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/node":
			if got := r.URL.Query().Get("user"); got != "alice" {
				t.Errorf("node user query = %q", got)
			}
			writeJSON(t, w, map[string]any{"nodes": []map[string]any{{"id": "9", "name": "laptop"}}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/node/9/rename/workstation":
			writeJSON(t, w, map[string]any{"node": map[string]any{"id": "9", "name": "client-hostname", "givenName": "workstation"}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/node/9/expire":
			switch expireCalls.Add(1) {
			case 1:
				if r.URL.Query().Get("expiry") == "" || r.URL.Query().Get("disableExpiry") != "" {
					t.Errorf("explicit node expiry query = %q", r.URL.RawQuery)
				}
			case 2:
				if r.URL.RawQuery != "" {
					t.Errorf("immediate node expiry must use server time; query = %q", r.URL.RawQuery)
				}
			case 3:
				if r.URL.Query().Get("disableExpiry") != "true" || r.URL.Query().Get("expiry") != "" {
					t.Errorf("disable node expiry query = %q", r.URL.RawQuery)
				}
			default:
				t.Errorf("unexpected node expiry call %d", expireCalls.Load())
			}
			writeJSON(t, w, map[string]any{"node": map[string]any{"id": "9", "expiry": r.URL.Query().Get("expiry")}})
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/node/9":
			writeJSON(t, w, map[string]any{})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/node/9/tags":
			body := decodeJSONMap(t, r)
			if tags, ok := body["tags"].([]any); !ok || len(tags) != 1 || tags[0] != "tag:server" {
				t.Errorf("set-tags body = %#v", body)
			}
			writeJSON(t, w, map[string]any{"node": map[string]any{"id": "9", "tags": []string{"tag:server"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/preauthkey":
			writeJSON(t, w, map[string]any{"preAuthKeys": []map[string]any{{"id": "11", "user": map[string]any{"id": "7", "name": "alice"}}}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/preauthkey":
			body := decodeJSONMap(t, r)
			if body["user"] != "7" || body["expiration"] == "" {
				t.Errorf("create preauth body = %#v", body)
			}
			writeJSON(t, w, map[string]any{"preAuthKey": map[string]any{"id": "11", "key": "hskey-auth-secret"}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/preauthkey/expire":
			if body := decodeJSONMap(t, r); body["id"] != "11" {
				t.Errorf("expire preauth body = %#v", body)
			}
			writeJSON(t, w, map[string]any{})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/apikey":
			writeJSON(t, w, map[string]any{"apiKeys": []map[string]any{{"id": "13", "prefix": "prefix"}}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/apikey":
			if body := decodeJSONMap(t, r); body["expiration"] == "" {
				t.Errorf("create API key body = %#v", body)
			}
			writeJSON(t, w, map[string]any{"apiKey": "api-secret"})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/apikey/expire":
			if body := decodeJSONMap(t, r); body["prefix"] != "prefix" {
				t.Errorf("expire API key body = %#v", body)
			}
			writeJSON(t, w, map[string]any{})
		default:
			http.Error(w, "unexpected route", http.StatusNotFound)
		}
	})
	_, client := newTLSTestClient(t, handler)
	ctx := context.Background()

	version, publicHealth, databaseHealth, info, err := client.Status(ctx)
	if err != nil || version.Version != "v0.29.3" || publicHealth.Status != "pass" || !databaseHealth.DatabaseConnectivity || info.TLSVersion == "" {
		t.Fatalf("Status() = %#v %#v %#v %#v, %v", version, publicHealth, databaseHealth, info, err)
	}
	users, err := client.ListUsers(ctx)
	if err != nil || len(users) != 1 || users[0].ID != "7" {
		t.Fatalf("ListUsers() = %#v, %v", users, err)
	}
	if _, err := client.CreateUser(ctx, CreateUserInput{Name: "alice"}); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	if _, err := client.RenameUser(ctx, "7", "new name"); err != nil {
		t.Fatalf("RenameUser() error = %v", err)
	}
	if err := client.DeleteUser(ctx, "7"); err != nil {
		t.Fatalf("DeleteUser() error = %v", err)
	}
	if _, err := client.ListNodes(ctx, "alice"); err != nil {
		t.Fatalf("ListNodes() error = %v", err)
	}
	renamed, err := client.RenameNode(ctx, "9", "workstation")
	if err != nil || renamed.GivenName != "workstation" || renamed.Name != "client-hostname" {
		t.Fatalf("RenameNode() = %#v, %v", renamed, err)
	}
	expiry := time.Date(2026, time.August, 22, 12, 0, 0, 0, time.UTC)
	if _, err := client.SetNodeExpiry(ctx, "9", &expiry, false); err != nil {
		t.Fatalf("SetNodeExpiry(expiry) error = %v", err)
	}
	if _, err := client.SetNodeExpiry(ctx, "9", nil, false); err != nil {
		t.Fatalf("SetNodeExpiry(immediate) error = %v", err)
	}
	if _, err := client.SetNodeExpiry(ctx, "9", nil, true); err != nil {
		t.Fatalf("SetNodeExpiry(disable) error = %v", err)
	}
	if _, err := client.SetNodeExpiry(ctx, "9", &expiry, true); err == nil {
		t.Fatal("SetNodeExpiry() accepted expiry and disable together")
	}
	if err := client.DeleteNode(ctx, "9"); err != nil {
		t.Fatalf("DeleteNode() error = %v", err)
	}
	if _, err := client.SetNodeTags(ctx, "9", []string{"tag:server"}); err != nil {
		t.Fatalf("SetNodeTags() error = %v", err)
	}
	if _, err := client.ListPreAuthKeys(ctx); err != nil {
		t.Fatalf("ListPreAuthKeys() error = %v", err)
	}
	if key, err := client.CreatePreAuthKey(ctx, CreatePreAuthKeyInput{User: "7", Expiration: expiry.Format(time.RFC3339)}); err != nil || key.Key != "hskey-auth-secret" {
		t.Fatalf("CreatePreAuthKey() = %#v, %v", key, err)
	}
	if err := client.ExpirePreAuthKey(ctx, "11"); err != nil {
		t.Fatalf("ExpirePreAuthKey() error = %v", err)
	}
	if _, err := client.ListAPIKeys(ctx); err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	if key, err := client.CreateAPIKey(ctx, expiry); err != nil || key != "api-secret" {
		t.Fatalf("CreateAPIKey() = %q, %v", key, err)
	}
	if err := client.ExpireAPIKey(ctx, "", "prefix"); err != nil {
		t.Fatalf("ExpireAPIKey() error = %v", err)
	}
}

func TestClientBoundsAndRedactsResponses(t *testing.T) {
	t.Run("error redaction", func(t *testing.T) {
		_, client := newTLSTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"api_key":"test-api-key"}`)
		}))
		_, err := client.ListUsers(context.Background())
		if err == nil || strings.Contains(err.Error(), "test-api-key") || !strings.Contains(err.Error(), "[REDACTED]") {
			t.Fatalf("ListUsers() error = %v", err)
		}
	})

	t.Run("successful body bound", func(t *testing.T) {
		_, client := newTLSTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, strings.Repeat("x", maxResponseBody+1))
		}))
		_, err := client.ListUsers(context.Background())
		if err == nil || !strings.Contains(err.Error(), "body exceeds") {
			t.Fatalf("ListUsers() error = %v", err)
		}
	})
}

func TestClientQueryEncoding(t *testing.T) {
	var got string
	_, client := newTLSTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.RawQuery
		writeJSON(t, w, map[string]any{"nodes": []any{}})
	}))
	if _, err := client.ListNodes(context.Background(), "name@example.com"); err != nil {
		t.Fatalf("ListNodes() error = %v", err)
	}
	values, err := url.ParseQuery(got)
	if err != nil || values.Get("user") != "name@example.com" {
		t.Fatalf("query = %q, %v", got, err)
	}
}

func writeJSON(t *testing.T, writer http.ResponseWriter, value any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Errorf("Encode() error = %v", err)
	}
}

func decodeJSONMap(t *testing.T, request *http.Request) map[string]any {
	t.Helper()
	defer request.Body.Close()
	var value map[string]any
	if err := json.NewDecoder(request.Body).Decode(&value); err != nil {
		t.Errorf("Decode() error = %v", err)
	}
	return value
}
