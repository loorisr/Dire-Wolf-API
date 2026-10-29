// Configuration loading for the Direwolf API bridge.
//
// Settings come from four sources, in increasing priority:
//
//  1. built-in defaults
//  2. a JSON configuration file
//  3. environment variables (DIREWOLF_CONFIG, DIREWOLF_FORWARD_TOKEN)
//  4. explicitly set command-line flags
//
// The configuration file is optional. When -config is not given, the loader
// looks for ./direwolf-api.json and then /etc/direwolf-api/config.json.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

// Duration is a time.Duration that (un)marshals as a string such as "10s".
type Duration time.Duration

// Std returns the value as a standard time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// UnmarshalJSON parses a duration string like "2s" or "500ms".
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New(`must be a duration string such as "10s"`)
	}
	if s == "" {
		*d = 0
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// MarshalJSON renders the duration as a string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// Config is the complete runtime configuration.
type Config struct {
	KISS       string        `json:"kiss"`
	API        string        `json:"api"`
	TLS        string        `json:"tls"`
	Cert       string        `json:"cert"`
	Key        string        `json:"key"`
	MaxPackets int           `json:"max_packets"`
	CSV        string        `json:"csv"`
	Forward    ForwardConfig `json:"forward"`
}

// ForwardConfig controls packet forwarding to a remote backend.
type ForwardConfig struct {
	URL            string   `json:"url"`
	HealthURL      string   `json:"health_url"`
	NodeID         string   `json:"node_id"`
	Token          string   `json:"token"`
	TokenFile      string   `json:"token_file"`
	SpoolDir       string   `json:"spool_dir"`
	SpoolMaxBytes  int64    `json:"spool_max_bytes"`
	Fsync          string   `json:"fsync"`
	Timeout        Duration `json:"timeout"`
	Queue          int      `json:"queue"`
	EnqueueTimeout Duration `json:"enqueue_timeout"`
	HealthInterval Duration `json:"health_interval"`
	Insecure       bool     `json:"insecure"`
}

// ConfigMeta describes where the configuration and the token came from.
type ConfigMeta struct {
	Path        string // configuration file actually loaded, "" if none
	TokenSource string // "env", "config", "file" or ""
}

// LoadedConfig bundles the configuration with its metadata.
type LoadedConfig struct {
	Config Config
	Meta   ConfigMeta
}

func defaultNodeID() string {
	h, err := os.Hostname()
	if err != nil || strings.TrimSpace(h) == "" {
		return "direwolf-api"
	}
	return h
}

// defaultConfig returns the built-in defaults.
func defaultConfig() Config {
	return Config{
		KISS:       "localhost:8001",
		API:        ":8080",
		MaxPackets: 1000,
		Forward: ForwardConfig{
			NodeID:         defaultNodeID(),
			SpoolDir:       "forward-spool",
			SpoolMaxBytes:  256 << 20,
			Fsync:          "always",
			Timeout:        Duration(10 * time.Second),
			Queue:          4096,
			EnqueueTimeout: Duration(2 * time.Second),
			HealthInterval: Duration(30 * time.Second),
		},
	}
}

// defaultConfigPaths returns the implicit configuration file locations.
func defaultConfigPaths() []string {
	paths := []string{"direwolf-api.json"}
	if runtime.GOOS != "windows" {
		paths = append(paths, "/etc/direwolf-api/config.json")
	}
	return paths
}

// configSearchPaths is a variable so tests can isolate the implicit lookup.
var configSearchPaths = defaultConfigPaths()

// loadConfig parses args and the environment into a Config.
func loadConfig(args []string, getenv func(string) string) (LoadedConfig, error) {
	def := defaultConfig()

	fs := flag.NewFlagSet("direwolf-api", flag.ContinueOnError)
	kiss := fs.String("kiss", def.KISS, "KISS source: host:port, tcp://, serial: (with optional ?baud=) or rfcomm://MAC|auto (channel auto via SDP; ?channel=N overrides)")
	apiAddr := fs.String("api", def.API, "API listen address")
	tlsAddr := fs.String("tls", def.TLS, "HTTPS/WSS listen address (disabled if empty)")
	certFile := fs.String("cert", def.Cert, "TLS certificate file (auto-generated if empty)")
	keyFile := fs.String("key", def.Key, "TLS private key file (auto-generated if empty)")
	maxPackets := fs.Int("max", def.MaxPackets, "Max packets to keep in memory")
	csvPath := fs.String("csv", def.CSV, "CSV output file path (disabled if empty)")
	configPath := fs.String("config", "", "JSON configuration file")

	fwdURL := fs.String("forward", def.Forward.URL, "Backend URL for packet forwarding (disabled if empty)")
	fwdHealth := fs.String("forward-health", def.Forward.HealthURL, "Backend health check URL (disabled if empty)")
	fwdNode := fs.String("forward-node", def.Forward.NodeID, "Station identifier sent to the backend")
	fwdTokenFile := fs.String("forward-token-file", def.Forward.TokenFile, "File containing the backend bearer token")
	fwdSpool := fs.String("forward-spool", def.Forward.SpoolDir, "Persistent spool directory")
	fwdSpoolMax := fs.Int64("forward-spool-max", def.Forward.SpoolMaxBytes, "Spool size cap in bytes")
	fwdFsync := fs.String("forward-fsync", def.Forward.Fsync, "Spool fsync mode: always, periodic or never")
	fwdTimeout := fs.Duration("forward-timeout", def.Forward.Timeout.Std(), "HTTP request timeout")
	fwdQueue := fs.Int("forward-queue", def.Forward.Queue, "In-memory queue size between ingest and spool")
	fwdEnqueueTimeout := fs.Duration("forward-enqueue-timeout", def.Forward.EnqueueTimeout.Std(), "Max time ingest waits for queue space")
	fwdHealthInterval := fs.Duration("forward-health-interval", def.Forward.HealthInterval.Std(), "Backend health check interval")
	fwdInsecure := fs.Bool("forward-insecure", def.Forward.Insecure, "Skip backend TLS certificate verification")

	if err := fs.Parse(args); err != nil {
		return LoadedConfig{}, err
	}

	visited := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { visited[f.Name] = true })

	cfg := defaultConfig()
	meta := ConfigMeta{}

	// Locate and load the configuration file.
	path := ""
	explicit := false
	switch {
	case visited["config"]:
		path, explicit = *configPath, true
	case getenv("DIREWOLF_CONFIG") != "":
		path, explicit = getenv("DIREWOLF_CONFIG"), true
	default:
		for _, candidate := range configSearchPaths {
			if _, err := os.Stat(candidate); err == nil {
				path = candidate
				break
			}
		}
	}

	if path != "" {
		if err := decodeConfigFile(path, &cfg); err != nil {
			if explicit || !errors.Is(err, os.ErrNotExist) {
				return LoadedConfig{}, err
			}
		} else {
			meta.Path = path
		}
	}

	// Command-line flags override the file, but only when explicitly set.
	if visited["kiss"] {
		cfg.KISS = *kiss
	}
	if visited["api"] {
		cfg.API = *apiAddr
	}
	if visited["tls"] {
		cfg.TLS = *tlsAddr
	}
	if visited["cert"] {
		cfg.Cert = *certFile
	}
	if visited["key"] {
		cfg.Key = *keyFile
	}
	if visited["max"] {
		cfg.MaxPackets = *maxPackets
	}
	if visited["csv"] {
		cfg.CSV = *csvPath
	}
	if visited["forward"] {
		cfg.Forward.URL = *fwdURL
	}
	if visited["forward-health"] {
		cfg.Forward.HealthURL = *fwdHealth
	}
	if visited["forward-node"] {
		cfg.Forward.NodeID = *fwdNode
	}
	if visited["forward-token-file"] {
		cfg.Forward.TokenFile = *fwdTokenFile
	}
	if visited["forward-spool"] {
		cfg.Forward.SpoolDir = *fwdSpool
	}
	if visited["forward-spool-max"] {
		cfg.Forward.SpoolMaxBytes = *fwdSpoolMax
	}
	if visited["forward-fsync"] {
		cfg.Forward.Fsync = *fwdFsync
	}
	if visited["forward-timeout"] {
		cfg.Forward.Timeout = Duration(*fwdTimeout)
	}
	if visited["forward-queue"] {
		cfg.Forward.Queue = *fwdQueue
	}
	if visited["forward-enqueue-timeout"] {
		cfg.Forward.EnqueueTimeout = Duration(*fwdEnqueueTimeout)
	}
	if visited["forward-health-interval"] {
		cfg.Forward.HealthInterval = Duration(*fwdHealthInterval)
	}
	if visited["forward-insecure"] {
		cfg.Forward.Insecure = *fwdInsecure
	}

	if cfg.Forward.URL != "" {
		token, source, err := resolveToken(cfg.Forward, getenv)
		if err != nil {
			return LoadedConfig{}, err
		}
		cfg.Forward.Token = token
		meta.TokenSource = source
	}

	if err := validateConfig(&cfg); err != nil {
		return LoadedConfig{}, err
	}

	return LoadedConfig{Config: cfg, Meta: meta}, nil
}

// decodeConfigFile reads path and decodes it into cfg. Unknown fields are
// rejected so typos in the hand-edited file are reported instead of ignored.
func decodeConfigFile(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return fmt.Errorf("config %s: %w", path, err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("config %s: unexpected data after the JSON object", path)
	}
	return nil
}

// resolveToken applies the token precedence: env, then config value, then file.
func resolveToken(f ForwardConfig, getenv func(string) string) (string, string, error) {
	if v := strings.TrimSpace(getenv("DIREWOLF_FORWARD_TOKEN")); v != "" {
		return v, "env", nil
	}
	if v := strings.TrimSpace(f.Token); v != "" {
		return v, "config", nil
	}
	if f.TokenFile != "" {
		data, err := os.ReadFile(f.TokenFile)
		if err != nil {
			return "", "", fmt.Errorf("forward token file %s: %w", f.TokenFile, err)
		}
		v := strings.TrimSpace(string(data))
		if v == "" {
			return "", "", fmt.Errorf("forward token file %s is empty", f.TokenFile)
		}
		return v, "file", nil
	}
	return "", "", nil
}

// validateConfig checks values that would otherwise fail at runtime.
func validateConfig(cfg *Config) error {
	if cfg.API == "" {
		return errors.New("config: api address must not be empty")
	}
	if _, err := parseKISSSource(cfg.KISS); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if cfg.MaxPackets < 1 {
		return errors.New("config: max_packets must be at least 1")
	}
	if (cfg.Cert == "") != (cfg.Key == "") {
		return errors.New("config: cert and key must be set together")
	}

	f := &cfg.Forward
	if _, err := parseFsyncMode(f.Fsync); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if f.URL == "" {
		return nil
	}
	if err := validateHTTPURL("forward url", f.URL); err != nil {
		return err
	}
	if f.HealthURL != "" {
		if err := validateHTTPURL("forward health_url", f.HealthURL); err != nil {
			return err
		}
		if f.HealthInterval <= 0 {
			return errors.New("config: forward health_interval must be greater than zero")
		}
	}
	if strings.TrimSpace(f.NodeID) == "" {
		f.NodeID = defaultNodeID()
	}
	if f.SpoolDir == "" {
		return errors.New("config: forward spool_dir must not be empty")
	}
	if f.SpoolMaxBytes < 1 {
		return errors.New("config: forward spool_max_bytes must be greater than zero")
	}
	if f.Queue < 1 {
		return errors.New("config: forward queue must be at least 1")
	}
	if f.Timeout <= 0 {
		return errors.New("config: forward timeout must be greater than zero")
	}
	if f.EnqueueTimeout < 0 {
		return errors.New("config: forward enqueue_timeout must not be negative")
	}
	if f.Token == "" {
		return errors.New("config: forward url is set but no token was provided " +
			"(set DIREWOLF_FORWARD_TOKEN, forward.token or forward.token_file)")
	}
	return nil
}

func validateHTTPURL(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("config: %s is invalid: %w", name, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("config: %s must use http or https (got %q)", name, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("config: %s is missing a host", name)
	}
	return nil
}
