package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func noEnv(string) string { return "" }

func isolateConfigSearch(t *testing.T) {
	t.Helper()
	old := configSearchPaths
	configSearchPaths = nil
	t.Cleanup(func() { configSearchPaths = old })
}

func TestExampleConfigLoads(t *testing.T) {
	// The repository example must stay loadable when copied verbatim.
	if _, err := loadConfig([]string{"-config", "config.example.json"}, noEnv); err != nil {
		t.Fatalf("config.example.json: %v", err)
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustLoad(t *testing.T, args []string, env map[string]string) LoadedConfig {
	t.Helper()
	loaded, err := loadConfig(args, func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	return loaded
}

func TestLoadConfigDefaults(t *testing.T) {
	isolateConfigSearch(t)
	loaded := mustLoad(t, nil, nil)
	cfg := loaded.Config

	if cfg.KISS != "localhost:8001" {
		t.Errorf("KISS = %q", cfg.KISS)
	}
	if cfg.API != ":8080" {
		t.Errorf("API = %q", cfg.API)
	}
	if cfg.MaxPackets != 1000 {
		t.Errorf("MaxPackets = %d", cfg.MaxPackets)
	}
	if cfg.Forward.URL != "" {
		t.Errorf("Forward.URL = %q", cfg.Forward.URL)
	}
	if got := cfg.Forward.Timeout.Std(); got != 10*time.Second {
		t.Errorf("Forward.Timeout = %s", got)
	}
	if got := cfg.Forward.HealthInterval.Std(); got != 30*time.Second {
		t.Errorf("Forward.HealthInterval = %s", got)
	}
	if cfg.Forward.SpoolMaxBytes != 256<<20 {
		t.Errorf("Forward.SpoolMaxBytes = %d", cfg.Forward.SpoolMaxBytes)
	}
	if loaded.Meta.Path != "" || loaded.Meta.TokenSource != "" {
		t.Errorf("unexpected meta: %+v", loaded.Meta)
	}
}

func TestLoadConfigFileAndDefaults(t *testing.T) {
	path := writeConfig(t, `{
		"kiss": "example:1234",
		"max_packets": 42,
		"forward": {
			"url": "https://backend.example/v1/packets",
			"token": "secret",
			"spool_dir": "/tmp/direwolf-spool"
		}
	}`)

	loaded := mustLoad(t, []string{"-config", path}, nil)
	cfg := loaded.Config

	if loaded.Meta.Path != path {
		t.Errorf("meta path = %q", loaded.Meta.Path)
	}
	if loaded.Meta.TokenSource != "config" {
		t.Errorf("token source = %q", loaded.Meta.TokenSource)
	}
	if cfg.KISS != "example:1234" || cfg.MaxPackets != 42 {
		t.Errorf("file values not applied: %+v", cfg)
	}
	if cfg.Forward.URL != "https://backend.example/v1/packets" || cfg.Forward.Token != "secret" {
		t.Errorf("forward values not applied: %+v", cfg.Forward)
	}
	// Values omitted from the file keep their defaults.
	if cfg.Forward.Queue != 4096 {
		t.Errorf("queue = %d, want default 4096", cfg.Forward.Queue)
	}
	if got := cfg.Forward.EnqueueTimeout.Std(); got != 2*time.Second {
		t.Errorf("enqueue timeout = %s", got)
	}
	if cfg.Forward.Fsync != "always" {
		t.Errorf("fsync = %q", cfg.Forward.Fsync)
	}
}

func TestLoadConfigUnknownField(t *testing.T) {
	path := writeConfig(t, `{"kiss": "x", "typo_field": true}`)
	if _, err := loadConfig([]string{"-config", path}, noEnv); err == nil {
		t.Fatal("expected an error for an unknown field")
	} else if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadConfigTrailingData(t *testing.T) {
	path := writeConfig(t, `{"kiss":"x"} {"kiss":"y"}`)
	if _, err := loadConfig([]string{"-config", path}, noEnv); err == nil {
		t.Fatal("expected an error for trailing JSON")
	}
}

func TestLoadConfigFlagOverridesFile(t *testing.T) {
	path := writeConfig(t, `{"kiss": "file:1", "api": ":9090"}`)

	loaded := mustLoad(t, []string{"-config", path, "-kiss", "flag:2"}, nil)
	if loaded.Config.KISS != "flag:2" {
		t.Errorf("KISS = %q, want flag value", loaded.Config.KISS)
	}
	if loaded.Config.API != ":9090" {
		t.Errorf("API = %q, want file value", loaded.Config.API)
	}
}

func TestLoadConfigEnvTokenWins(t *testing.T) {
	path := writeConfig(t, `{
		"forward": {"url": "https://backend.example/v1/packets", "token": "from-file"}
	}`)

	loaded := mustLoad(t, []string{"-config", path}, map[string]string{
		"DIREWOLF_FORWARD_TOKEN": "from-env",
	})
	if loaded.Config.Forward.Token != "from-env" {
		t.Errorf("token = %q", loaded.Config.Forward.Token)
	}
	if loaded.Meta.TokenSource != "env" {
		t.Errorf("source = %q", loaded.Meta.TokenSource)
	}
}

func TestLoadConfigTokenFile(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("  file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, fmt.Sprintf(`{
		"forward": {
			"url": "https://backend.example/v1/packets",
			"token_file": %q,
			"spool_dir": %q
		}
	}`, tokenPath, t.TempDir()))

	loaded := mustLoad(t, []string{"-config", path}, nil)
	if loaded.Config.Forward.Token != "file-token" {
		t.Errorf("token = %q", loaded.Config.Forward.Token)
	}
	if loaded.Meta.TokenSource != "file" {
		t.Errorf("source = %q", loaded.Meta.TokenSource)
	}
}

func TestLoadConfigMissingTokenFile(t *testing.T) {
	path := writeConfig(t, `{
		"forward": {
			"url": "https://backend.example/v1/packets",
			"token_file": "/nonexistent/token"
		}
	}`)
	if _, err := loadConfig([]string{"-config", path}, noEnv); err == nil {
		t.Fatal("expected an error for a missing token file")
	}
}

func TestLoadConfigMissingForwardToken(t *testing.T) {
	path := writeConfig(t, `{"forward": {"url": "https://backend.example/v1/packets"}}`)
	if _, err := loadConfig([]string{"-config", path}, noEnv); err == nil {
		t.Fatal("expected an error when the forward URL has no token")
	}
}

func TestLoadConfigInvalidURL(t *testing.T) {
	path := writeConfig(t, `{"forward": {"url": "ftp://example/v1", "token": "x"}}`)
	if _, err := loadConfig([]string{"-config", path}, noEnv); err == nil {
		t.Fatal("expected an error for a non-HTTP URL")
	}
}

func TestLoadConfigInvalidDuration(t *testing.T) {
	path := writeConfig(t, `{"forward": {"timeout": "soon"}}`)
	if _, err := loadConfig([]string{"-config", path}, noEnv); err == nil {
		t.Fatal("expected an error for an invalid duration")
	}
}

func TestLoadConfigInvalidFsync(t *testing.T) {
	path := writeConfig(t, `{"forward": {"fsync": "sometimes"}}`)
	if _, err := loadConfig([]string{"-config", path}, noEnv); err == nil {
		t.Fatal("expected an error for an invalid fsync mode")
	}
}

func TestLoadConfigExplicitMissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.json")
	if _, err := loadConfig([]string{"-config", missing}, noEnv); err == nil {
		t.Fatal("expected an error for an explicit missing config file")
	}
}

func TestLoadConfigFromEnvironment(t *testing.T) {
	path := writeConfig(t, `{"kiss": "env-file:1"}`)
	loaded := mustLoad(t, nil, map[string]string{"DIREWOLF_CONFIG": path})
	if loaded.Config.KISS != "env-file:1" {
		t.Errorf("KISS = %q", loaded.Config.KISS)
	}
	if loaded.Meta.Path != path {
		t.Errorf("path = %q", loaded.Meta.Path)
	}
}
