package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	requestTimeout        = 10 * time.Second
	maxResponseHeaders    = 64 * 1024
	maxResponseBody       = 8 * 1024 * 1024
	maxErrorBody          = 4096
	responseHeaderTimeout = 5 * time.Second
	tlsHandshakeTimeout   = 5 * time.Second
	dialTimeout           = 5 * time.Second
)

type Client struct {
	baseURL    *url.URL
	apiKey     string
	httpClient *http.Client
}

type ResponseInfo struct {
	TLSVersion string
	Subject    string
	DNSNames   []string
	NotAfter   time.Time
}

type GoInfo struct {
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

type VersionInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"buildTime"`
	Go        GoInfo `json:"go"`
	Dirty     bool   `json:"dirty"`
}

type User struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	CreatedAt   string `json:"createdAt"`
}

type Node struct {
	ID          string   `json:"id"`
	IPAddresses []string `json:"ipAddresses"`
	Name        string   `json:"name"`
	GivenName   string   `json:"givenName"`
	User        User     `json:"user"`
	Online      bool     `json:"online"`
	Expiry      string   `json:"expiry"`
	Tags        []string `json:"tags"`
}

type PreAuthKey struct {
	User       User     `json:"user"`
	ID         string   `json:"id"`
	Key        string   `json:"key"`
	Reusable   bool     `json:"reusable"`
	Ephemeral  bool     `json:"ephemeral"`
	Used       bool     `json:"used"`
	Expiration string   `json:"expiration"`
	CreatedAt  string   `json:"createdAt"`
	ACLTags    []string `json:"aclTags"`
}

type APIKey struct {
	ID         string `json:"id"`
	Prefix     string `json:"prefix"`
	Expiration string `json:"expiration"`
	CreatedAt  string `json:"createdAt"`
	LastSeen   string `json:"lastSeen"`
}

type Health struct {
	Status               string `json:"status"`
	DatabaseConnectivity bool   `json:"databaseConnectivity"`
}

type CreateUserInput struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
	Email       string `json:"email,omitempty"`
	PictureURL  string `json:"pictureUrl,omitempty"`
}

type CreatePreAuthKeyInput struct {
	User       string   `json:"user"`
	Reusable   bool     `json:"reusable"`
	Ephemeral  bool     `json:"ephemeral"`
	Expiration string   `json:"expiration"`
	ACLTags    []string `json:"aclTags,omitempty"`
}

func newHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.TLSHandshakeTimeout = tlsHandshakeTimeout
	transport.ResponseHeaderTimeout = responseHeaderTimeout
	transport.MaxResponseHeaderBytes = maxResponseHeaders
	return &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func NewClient(config Config, httpClient *http.Client) (*Client, error) {
	config, err := validateConfig(config)
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(config.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("parse server URL: %w", err)
	}
	if httpClient == nil {
		httpClient = newHTTPClient()
	}
	return &Client{baseURL: parsed, apiKey: config.APIKey, httpClient: httpClient}, nil
}

func (client *Client) do(ctx context.Context, method, path string, query url.Values, body any, authenticated bool, out any) (ResponseInfo, error) {
	endpoint := *client.baseURL
	decodedPath, err := url.PathUnescape(path)
	if err != nil {
		return ResponseInfo{}, fmt.Errorf("prepare request path: %w", err)
	}
	endpoint.Path = decodedPath
	endpoint.RawPath = path
	if query != nil {
		endpoint.RawQuery = query.Encode()
	}

	var requestBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return ResponseInfo{}, fmt.Errorf("encode request: %w", err)
		}
		requestBody = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), requestBody)
	if err != nil {
		return ResponseInfo{}, fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "headscale-ops/"+buildVersion)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if authenticated {
		request.Header.Set("Authorization", "Bearer "+client.apiKey)
	}

	response, err := client.httpClient.Do(request)
	if err != nil {
		return ResponseInfo{}, fmt.Errorf("request %s %s: %w", method, path, unwrapURLError(err))
	}
	defer response.Body.Close()
	info := responseTLSInfo(response)

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		excerpt := readErrorExcerpt(response.Body, client.apiKey)
		return info, fmt.Errorf("request %s %s returned HTTP %d: %s", method, path, response.StatusCode, excerpt)
	}

	contents, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBody+1))
	if err != nil {
		return info, fmt.Errorf("read response %s: %w", path, err)
	}
	if len(contents) > maxResponseBody {
		return info, fmt.Errorf("read response %s: body exceeds %d bytes", path, maxResponseBody)
	}
	if out != nil && len(bytes.TrimSpace(contents)) > 0 {
		if err := json.Unmarshal(contents, out); err != nil {
			return info, fmt.Errorf("decode response %s: %w", path, err)
		}
	}
	return info, nil
}

func unwrapURLError(err error) error {
	var urlError *url.Error
	if errors.As(err, &urlError) {
		return urlError.Err
	}
	return err
}

func readErrorExcerpt(body io.Reader, apiKey string) string {
	contents, err := io.ReadAll(io.LimitReader(body, maxErrorBody+1))
	if err != nil {
		return "response body unreadable"
	}
	if len(contents) > maxErrorBody {
		contents = contents[:maxErrorBody]
	}
	text := string(contents)
	if apiKey != "" {
		text = strings.ReplaceAll(text, apiKey, "[REDACTED]")
	}
	text = safeText(strings.Join(strings.Fields(text), " "))
	if text == "" {
		return "response body empty"
	}
	return text
}

func responseTLSInfo(response *http.Response) ResponseInfo {
	if response == nil || response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
		return ResponseInfo{}
	}
	certificate := response.TLS.PeerCertificates[0]
	dnsNames := append([]string(nil), certificate.DNSNames...)
	sort.Strings(dnsNames)
	return ResponseInfo{
		TLSVersion: tlsVersionName(response.TLS.Version),
		Subject:    certificate.Subject.String(),
		DNSNames:   dnsNames,
		NotAfter:   certificate.NotAfter,
	}
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func (client *Client) Status(ctx context.Context) (VersionInfo, Health, Health, ResponseInfo, error) {
	var publicHealth Health
	info, err := client.do(ctx, http.MethodGet, "/health", nil, nil, false, &publicHealth)
	if err != nil {
		return VersionInfo{}, Health{}, Health{}, info, err
	}
	var version VersionInfo
	_, err = client.do(ctx, http.MethodGet, "/version", nil, nil, false, &version)
	if err != nil {
		return VersionInfo{}, publicHealth, Health{}, info, err
	}
	var databaseHealth Health
	_, err = client.do(ctx, http.MethodGet, "/api/v1/health", nil, nil, true, &databaseHealth)
	if err != nil {
		return version, publicHealth, Health{}, info, err
	}
	return version, publicHealth, databaseHealth, info, nil
}

func (client *Client) ListUsers(ctx context.Context) ([]User, error) {
	var response struct {
		Users []User `json:"users"`
	}
	_, err := client.do(ctx, http.MethodGet, "/api/v1/user", nil, nil, true, &response)
	return response.Users, err
}

func (client *Client) CreateUser(ctx context.Context, input CreateUserInput) (User, error) {
	var response struct {
		User User `json:"user"`
	}
	_, err := client.do(ctx, http.MethodPost, "/api/v1/user", nil, input, true, &response)
	return response.User, err
}

func (client *Client) RenameUser(ctx context.Context, id, name string) (User, error) {
	path := "/api/v1/user/" + url.PathEscape(id) + "/rename/" + url.PathEscape(name)
	var response struct {
		User User `json:"user"`
	}
	_, err := client.do(ctx, http.MethodPost, path, nil, nil, true, &response)
	return response.User, err
}

func (client *Client) DeleteUser(ctx context.Context, id string) error {
	_, err := client.do(ctx, http.MethodDelete, "/api/v1/user/"+url.PathEscape(id), nil, nil, true, nil)
	return err
}

func (client *Client) ListNodes(ctx context.Context, user string) ([]Node, error) {
	query := url.Values{}
	if user != "" {
		query.Set("user", user)
	}
	var response struct {
		Nodes []Node `json:"nodes"`
	}
	_, err := client.do(ctx, http.MethodGet, "/api/v1/node", query, nil, true, &response)
	return response.Nodes, err
}

func (client *Client) RenameNode(ctx context.Context, id, name string) (Node, error) {
	path := "/api/v1/node/" + url.PathEscape(id) + "/rename/" + url.PathEscape(name)
	var response struct {
		Node Node `json:"node"`
	}
	_, err := client.do(ctx, http.MethodPost, path, nil, nil, true, &response)
	return response.Node, err
}

func (client *Client) SetNodeExpiry(ctx context.Context, id string, expiry *time.Time, disable bool) (Node, error) {
	if disable && expiry != nil {
		return Node{}, errors.New("cannot set an expiry while disabling node expiry")
	}
	query := url.Values{}
	if disable {
		query.Set("disableExpiry", "true")
	} else if expiry != nil {
		query.Set("expiry", expiry.UTC().Format(time.RFC3339))
	}
	var response struct {
		Node Node `json:"node"`
	}
	path := "/api/v1/node/" + url.PathEscape(id) + "/expire"
	_, err := client.do(ctx, http.MethodPost, path, query, nil, true, &response)
	return response.Node, err
}

func (client *Client) DeleteNode(ctx context.Context, id string) error {
	_, err := client.do(ctx, http.MethodDelete, "/api/v1/node/"+url.PathEscape(id), nil, nil, true, nil)
	return err
}

func (client *Client) SetNodeTags(ctx context.Context, id string, tags []string) (Node, error) {
	var response struct {
		Node Node `json:"node"`
	}
	path := "/api/v1/node/" + url.PathEscape(id) + "/tags"
	body := struct {
		Tags []string `json:"tags"`
	}{Tags: tags}
	_, err := client.do(ctx, http.MethodPost, path, nil, body, true, &response)
	return response.Node, err
}

func (client *Client) ListPreAuthKeys(ctx context.Context) ([]PreAuthKey, error) {
	var response struct {
		PreAuthKeys []PreAuthKey `json:"preAuthKeys"`
	}
	_, err := client.do(ctx, http.MethodGet, "/api/v1/preauthkey", nil, nil, true, &response)
	return response.PreAuthKeys, err
}

func (client *Client) CreatePreAuthKey(ctx context.Context, input CreatePreAuthKeyInput) (PreAuthKey, error) {
	var response struct {
		PreAuthKey PreAuthKey `json:"preAuthKey"`
	}
	_, err := client.do(ctx, http.MethodPost, "/api/v1/preauthkey", nil, input, true, &response)
	return response.PreAuthKey, err
}

func (client *Client) ExpirePreAuthKey(ctx context.Context, id string) error {
	body := struct {
		ID string `json:"id"`
	}{ID: id}
	_, err := client.do(ctx, http.MethodPost, "/api/v1/preauthkey/expire", nil, body, true, nil)
	return err
}

func (client *Client) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	var response struct {
		APIKeys []APIKey `json:"apiKeys"`
	}
	_, err := client.do(ctx, http.MethodGet, "/api/v1/apikey", nil, nil, true, &response)
	return response.APIKeys, err
}

func (client *Client) CreateAPIKey(ctx context.Context, expiration time.Time) (string, error) {
	body := struct {
		Expiration string `json:"expiration"`
	}{Expiration: expiration.UTC().Format(time.RFC3339)}
	var response struct {
		APIKey string `json:"apiKey"`
	}
	_, err := client.do(ctx, http.MethodPost, "/api/v1/apikey", nil, body, true, &response)
	return response.APIKey, err
}

func (client *Client) ExpireAPIKey(ctx context.Context, id, prefix string) error {
	body := struct {
		Prefix string `json:"prefix,omitempty"`
		ID     string `json:"id,omitempty"`
	}{Prefix: prefix, ID: id}
	_, err := client.do(ctx, http.MethodPost, "/api/v1/apikey/expire", nil, body, true, nil)
	return err
}
