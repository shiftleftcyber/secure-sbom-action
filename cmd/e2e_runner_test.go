package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLI_SignSBOM_E2E(t *testing.T) {
	tmpDir := t.TempDir()

	// Create SBOM input
	sbomPath := filepath.Join(tmpDir, "test.json")
	err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX"}`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Fake SecureSBOM API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if r.URL.Path != "/api/v1/sbom/sign" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"signed":true}`))
	}))
	defer server.Close()

	// Build binary
	binPath := filepath.Join(tmpDir, "secure-sbom-action")

	build := exec.Command("go", "build", "-o", binPath, "./")
	build.Env = os.Environ()

	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	// Run binary with env vars
	cmd := exec.Command(binPath)

	cmd.Env = append(os.Environ(),
		"SECURE_SBOM_API_URL="+server.URL,
		"SECURE_SBOM_API_KEY=test-api-key",
		"SECURE_SBOM_ACTION=sign",
		"SECURE_SBOM_SIGNING_KEY_ID=test-key",
		"SBOM_FILE="+sbomPath,
		"SECURE_SBOM_USE_V1_API=true",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\n%s", err, string(output))
	}

	// Validate output file
	signedPath := signedOutputPath(sbomPath)

	data, err := os.ReadFile(signedPath)
	if err != nil {
		t.Fatalf("expected signed output file: %v", err)
	}

	if string(data) != `{"signed":true}` {
		t.Fatalf("unexpected signed output: %s", string(data))
	}

	// Validate CLI output
	if !strings.Contains(string(output), "SBOM signed successfully") {
		t.Fatalf("unexpected stdout: %s", string(output))
	}
}

func TestCLI_InvalidAPIKey_Fails(t *testing.T) {
	tmpDir := t.TempDir()

	sbomPath := writeTempFile(t, tmpDir, "test.json", `{"bomFormat":"CycloneDX"}`)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	binPath := filepath.Join(tmpDir, "secure-sbom-action")

	err := exec.Command("go", "build", "-o", binPath, "./").Run()
	if err != nil {
		t.Fatalf("Run Error")
	}

	cmd := exec.Command(binPath)

	cmd.Env = append(os.Environ(),
		"SECURE_SBOM_API_URL="+server.URL,
		"SECURE_SBOM_API_KEY=badkey",
		"SECURE_SBOM_ACTION=sign",
		"SECURE_SBOM_SIGNING_KEY_ID=test",
		"SBOM_FILE="+sbomPath,
	)

	output, err := cmd.CombinedOutput()

	if err == nil {
		t.Fatalf("expected failure")
	}

	if !strings.Contains(string(output), "API error") {
		t.Fatalf("unexpected output: %s", string(output))
	}
}
