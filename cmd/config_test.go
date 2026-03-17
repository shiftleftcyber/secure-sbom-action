package main

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

func TestLoadRunOptionsFromEnv_UsesNewEnvNames(t *testing.T) {
	t.Setenv("SECURE_SBOM_API_KEY", "new-api-key")
	t.Setenv("SECURE_SBOM_ACTION", "sign")
	t.Setenv("SECURE_SBOM_SIGNING_KEY_ID", "new-key-id")
	t.Setenv("SBOM_FILE", "test.cdx.json")

	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	opts, err := LoadRunOptionsFromEnv(logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if opts.SecureSBOMAPIKey != "new-api-key" {
		t.Fatalf("expected new api key, got %q", opts.SecureSBOMAPIKey)
	}

	if opts.SigningKeyID != "new-key-id" {
		t.Fatalf("expected new key id, got %q", opts.SigningKeyID)
	}

	if opts.Action != ActionSign {
		t.Fatalf("expected action %q, got %q", ActionSign, opts.Action)
	}

	if opts.SBOMFilePath != "test.cdx.json" {
		t.Fatalf("expected sbom file path to be set, got %q", opts.SBOMFilePath)
	}

	if opts.SecureSBOMAPIURL != defaultGatewayURL {
		t.Fatalf("expected default gateway url, got %q", opts.SecureSBOMAPIURL)
	}

	if got := buf.String(); got != "" {
		t.Fatalf("expected no warnings, got %q", got)
	}
}

func TestLoadRunOptionsFromEnv_FallsBackToLegacyAndWarns(t *testing.T) {
	t.Setenv("API_KEY", "legacy-api-key")
	t.Setenv("ACTION", "sign")
	t.Setenv("KEY_ID", "legacy-key-id")
	t.Setenv("SBOM_FILE", "legacy.cdx.json")
	t.Setenv("API_URL", "https://legacy.example.com")

	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	opts, err := LoadRunOptionsFromEnv(logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if opts.SecureSBOMAPIKey != "legacy-api-key" {
		t.Fatalf("expected legacy api key, got %q", opts.SecureSBOMAPIKey)
	}

	if opts.SigningKeyID != "legacy-key-id" {
		t.Fatalf("expected legacy key id, got %q", opts.SigningKeyID)
	}

	if opts.SecureSBOMAPIURL != "https://legacy.example.com" {
		t.Fatalf("expected legacy api url, got %q", opts.SecureSBOMAPIURL)
	}

	logs := buf.String()
	expectedWarnings := []string{
		"API_KEY is deprecated; use SECURE_SBOM_API_KEY instead",
		"ACTION is deprecated; use SECURE_SBOM_ACTION instead",
		"KEY_ID is deprecated; use SECURE_SBOM_SIGNING_KEY_ID instead",
		"API_URL is deprecated; use SECURE_SBOM_API_URL instead",
	}

	for _, expected := range expectedWarnings {
		if !strings.Contains(logs, expected) {
			t.Fatalf("expected warning %q in logs: %q", expected, logs)
		}
	}
}

func TestLoadRunOptionsFromEnv_NewTakesPrecedenceOverLegacy(t *testing.T) {
	t.Setenv("SECURE_SBOM_API_KEY", "new-api-key")
	t.Setenv("API_KEY", "legacy-api-key")
	t.Setenv("SECURE_SBOM_ACTION", "sign")
	t.Setenv("ACTION", "verify")
	t.Setenv("SECURE_SBOM_SIGNING_KEY_ID", "new-key-id")
	t.Setenv("KEY_ID", "legacy-key-id")
	t.Setenv("SBOM_FILE", "test.cdx.json")

	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	opts, err := LoadRunOptionsFromEnv(logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if opts.SecureSBOMAPIKey != "new-api-key" {
		t.Fatalf("expected new api key, got %q", opts.SecureSBOMAPIKey)
	}

	if opts.Action != ActionSign {
		t.Fatalf("expected new action %q, got %q", ActionSign, opts.Action)
	}

	if opts.SigningKeyID != "new-key-id" {
		t.Fatalf("expected new key id, got %q", opts.SigningKeyID)
	}

	if got := buf.String(); got != "" {
		t.Fatalf("expected no warnings when new vars are present, got %q", got)
	}
}

func TestLoadRunOptionsFromEnv_SignDigestRequiresDigestAndKeyID(t *testing.T) {
	t.Setenv("SECURE_SBOM_API_KEY", "api-key")
	t.Setenv("SECURE_SBOM_ACTION", "sign_digest")
	t.Setenv("SECURE_SBOM_SIGNING_KEY_ID", "key-id")
	t.Setenv("DIGEST", "abcd1234")
	t.Setenv("DIGEST_HASH_ALGORITHM", "sha256")

	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	opts, err := LoadRunOptionsFromEnv(logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if opts.Digest != "abcd1234" {
		t.Fatalf("expected digest to be set, got %q", opts.Digest)
	}

	if opts.SBOMFilePath != "" {
		t.Fatalf("expected no sbom file path for sign_digest, got %q", opts.SBOMFilePath)
	}
}

func TestLoadRunOptionsFromEnv_MissingRequiredVars(t *testing.T) {
	clearRelevantEnv(t)

	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	_, err := LoadRunOptionsFromEnv(logger)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	msg := err.Error()
	expected := []string{
		"missing required environment variable SECURE_SBOM_API_KEY (legacy: API_KEY)",
		"missing required environment variable SECURE_SBOM_ACTION (legacy: ACTION)",
	}

	for _, want := range expected {
		if !strings.Contains(msg, want) {
			t.Fatalf("expected error to contain %q, got %q", want, msg)
		}
	}
}

func TestLoadRunOptionsFromEnv_InvalidAction(t *testing.T) {
	t.Setenv("SECURE_SBOM_API_KEY", "api-key")
	t.Setenv("SECURE_SBOM_ACTION", "do_something")
	t.Setenv("SBOM_FILE", "whatever.json")

	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	_, err := LoadRunOptionsFromEnv(logger)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), `invalid action "do_something"`) {
		t.Fatalf("expected invalid action error, got %q", err.Error())
	}
}

func TestLoadRunOptionsFromEnv_SignRequiresKeyIDAndSBOMFile(t *testing.T) {
	t.Setenv("SECURE_SBOM_API_KEY", "api-key")
	t.Setenv("SECURE_SBOM_ACTION", "sign")

	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	_, err := LoadRunOptionsFromEnv(logger)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	msg := err.Error()
	expected := []string{
		"missing required environment variable SECURE_SBOM_SIGNING_KEY_ID (legacy: KEY_ID)",
		"missing required environment variable SBOM_FILE",
	}

	for _, want := range expected {
		if !strings.Contains(msg, want) {
			t.Fatalf("expected error to contain %q, got %q", want, msg)
		}
	}
}

func clearRelevantEnv(t *testing.T) {
	t.Helper()

	keys := []string{
		"SECURE_SBOM_API_KEY",
		"API_KEY",
		"SECURE_SBOM_API_URL",
		"API_URL",
		"SECURE_SBOM_SIGNING_KEY_ID",
		"KEY_ID",
		"SECURE_SBOM_ACTION",
		"ACTION",
		"SBOM_FILE",
		"DIGEST",
	}

	for _, k := range keys {
		_ = os.Unsetenv(k)
	}
}
