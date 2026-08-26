package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const maxConfigBytes = 64 * 1024

type Config struct {
	ServerURL string `json:"server_url"`
	APIKey    string `json:"api_key"`
}

func defaultConfigPath() (string, error) {
	if override := strings.TrimSpace(os.Getenv("HEADSCALE_OPS_CONFIG")); override != "" {
		return filepath.Clean(override), nil
	}
	directory, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate user config directory: %w", err)
	}
	return filepath.Join(directory, "headscale-ops", "config.json"), nil
}

func normalizeServerURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid server URL: %w", err)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "https" {
		return "", errors.New("server URL must use https")
	}
	if parsed.Opaque != "" || parsed.Host == "" || parsed.Hostname() == "" {
		return "", errors.New("server URL must be absolute and include a host")
	}
	if parsed.User != nil {
		return "", errors.New("server URL must not include user information")
	}
	if parsed.ForceQuery || parsed.RawQuery != "" || parsed.Fragment != "" || strings.Contains(raw, "#") {
		return "", errors.New("server URL must not include a query or fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", errors.New("server URL must not include a path")
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return "", errors.New("server URL port must not be empty")
	}
	parsed.Path = ""
	parsed.RawPath = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

func validateConfig(config Config) (Config, error) {
	serverURL, err := normalizeServerURL(config.ServerURL)
	if err != nil {
		return Config{}, err
	}
	if strings.TrimSpace(config.APIKey) == "" {
		return Config{}, errors.New("API key must not be empty")
	}
	if strings.ContainsAny(config.APIKey, "\r\n\x00") {
		return Config{}, errors.New("API key must not contain CR, LF, or NUL")
	}
	config.ServerURL = serverURL
	return config, nil
}

func readConfig(path string) (Config, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return Config{}, errors.New("read config: symbolic links are not allowed")
	}
	if !info.Mode().IsRegular() {
		return Config{}, errors.New("read config: path is not a regular file")
	}
	if permissions := info.Mode().Perm(); permissions&0o077 != 0 {
		return Config{}, fmt.Errorf("read config: permissions %04o allow group or other access; require 0600", permissions)
	}

	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if !os.SameFile(info, openedInfo) {
		return Config{}, errors.New("read config: file changed while opening")
	}

	contents, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if len(contents) > maxConfigBytes {
		return Config{}, fmt.Errorf("read config: file exceeds %d bytes", maxConfigBytes)
	}

	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("read config: decode: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Config{}, fmt.Errorf("read config: decode: %w", err)
	}
	config, err = validateConfig(config)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	return config, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func writeConfig(path string, config Config) error {
	config, err := validateConfig(config)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	directoryInfo, err := os.Lstat(directory)
	createdDirectory := false
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return fmt.Errorf("create config directory: %w", err)
		}
		createdDirectory = true
		directoryInfo, err = os.Lstat(directory)
	}
	if err != nil {
		return fmt.Errorf("inspect config directory: %w", err)
	}
	if directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() {
		return errors.New("config directory must be a real directory, not a symbolic link")
	}
	if createdDirectory {
		if err := os.Chmod(directory, 0o700); err != nil {
			return fmt.Errorf("secure config directory: %w", err)
		}
		directoryInfo, err = os.Lstat(directory)
		if err != nil {
			return fmt.Errorf("inspect config directory: %w", err)
		}
	}
	if permissions := directoryInfo.Mode().Perm(); permissions&0o077 != 0 {
		return fmt.Errorf("config directory permissions %04o allow group or other access; require owner-only permissions", permissions)
	}

	if existing, err := os.Lstat(path); err == nil {
		if existing.Mode()&os.ModeSymlink != 0 || !existing.Mode().IsRegular() {
			return errors.New("existing config must be a regular file, not a symbolic link")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect existing config: %w", err)
	}

	contents, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	contents = append(contents, '\n')

	temporary, err := os.CreateTemp(directory, ".config-*")
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("secure temporary config: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary config: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary config: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary config: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}

	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open config directory: %w", err)
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return fmt.Errorf("sync config directory: %w", err)
	}
	return nil
}
