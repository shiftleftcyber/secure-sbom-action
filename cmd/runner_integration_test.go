package main

import (
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempFile(t *testing.T, dir, name, contents string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	return path
}

func TestRun_V1Sign_MultipartAndWritesSignedFile(t *testing.T) {
	tmpDir := t.TempDir()
	sbomPath := writeTempFile(t, tmpDir, "test.json", `{"bomFormat":"CycloneDX"}`)

	var gotPath string
	var gotAPIKey string
	var gotContentType string
	var gotKeyID string
	var gotSBOM string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAPIKey = r.Header.Get("x-api-key")
		gotContentType = r.Header.Get("Content-Type")

		mediaType, params, err := mime.ParseMediaType(gotContentType)
		if err != nil {
			t.Fatalf("failed to parse content-type: %v", err)
		}
		if mediaType != "multipart/form-data" {
			t.Fatalf("expected multipart/form-data, got %q", mediaType)
		}

		mr := multipart.NewReader(r.Body, params["boundary"])

		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("failed reading multipart: %v", err)
			}

			data, err := io.ReadAll(part)
			if err != nil {
				t.Fatalf("failed reading part: %v", err)
			}

			switch part.FormName() {
			case "key_id":
				gotKeyID = string(data)
			case "sbom":
				gotSBOM = string(data)
			}
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"signed":true}`))
	}))
	defer server.Close()

	opts := RunOptions{
		SecureSBOMAPIURL: server.URL,
		SecureSBOMAPIKey: "api-key-123",
		SigningKeyID:     "key-123",
		Action:           ActionSign,
		SBOMFilePath:     sbomPath,
		UseV1API:         true,
	}

	err := run(opts, server.Client())
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	if gotPath != "/"+signPath {
		t.Fatalf("expected path %q, got %q", "/"+signPath, gotPath)
	}
	if gotAPIKey != "api-key-123" {
		t.Fatalf("expected api key header, got %q", gotAPIKey)
	}
	if gotKeyID != "key-123" {
		t.Fatalf("expected key_id, got %q", gotKeyID)
	}
	if !strings.Contains(gotSBOM, `"bomFormat":"CycloneDX"`) {
		t.Fatalf("expected sbom payload, got %q", gotSBOM)
	}

	outputPath := signedOutputPath(sbomPath)
	written, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("expected signed output file: %v", err)
	}
	if string(written) != `{"signed":true}` {
		t.Fatalf("unexpected signed output: %q", string(written))
	}
}

func TestRun_V1Verify_Multipart(t *testing.T) {
	tmpDir := t.TempDir()
	sbomPath := writeTempFile(t, tmpDir, "test.json", `{"bomFormat":"CycloneDX"}`)

	var gotPath string
	var gotContentType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")

		mediaType, _, err := mime.ParseMediaType(gotContentType)
		if err != nil {
			t.Fatalf("failed to parse content-type: %v", err)
		}
		if mediaType != "multipart/form-data" {
			t.Fatalf("expected multipart/form-data, got %q", mediaType)
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"verified":true}`))
	}))
	defer server.Close()

	opts := RunOptions{
		SecureSBOMAPIURL: server.URL,
		SecureSBOMAPIKey: "api-key-123",
		Action:           ActionVerify,
		SBOMFilePath:     sbomPath,
		UseV1API:         true,
	}

	err := run(opts, server.Client())
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	if gotPath != "/"+verifyPath {
		t.Fatalf("expected path %q, got %q", "/"+verifyPath, gotPath)
	}
}

func TestRun_V2Sign_JSONAndWritesSignedFile(t *testing.T) {
	tmpDir := t.TempDir()
	sbomPath := writeTempFile(t, tmpDir, "test.json", `{"bomFormat":"CycloneDX"}`)

	var gotPath string
	var gotAPIKey string
	var gotBody []byte
	var gotContentType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAPIKey = r.Header.Get("x-api-key")
		gotContentType = r.Header.Get("Content-Type")

		var err error
		gotBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed reading body: %v", err)
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"signed_sbom":{"bomFormat":"CycloneDX","signature":"abc123"}}`))
	}))
	defer server.Close()

	opts := RunOptions{
		SecureSBOMAPIURL: server.URL,
		SecureSBOMAPIKey: "api-key-123",
		SigningKeyID:     "key-123",
		Action:           ActionSign,
		SBOMFilePath:     sbomPath,
		UseV1API:         false,
	}

	err := run(opts, server.Client())
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	if gotPath != "/"+signPathV2 {
		t.Fatalf("expected path %q, got %q", "/"+signPathV2, gotPath)
	}
	if gotAPIKey != "api-key-123" {
		t.Fatalf("expected api key header, got %q", gotAPIKey)
	}
	if gotContentType != "application/json" {
		t.Fatalf("expected application/json, got %q", gotContentType)
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(gotBody, &payload); err != nil {
		t.Fatalf("failed to unmarshal request: %v", err)
	}

	var keyID string
	if err := json.Unmarshal(payload["key_id"], &keyID); err != nil {
		t.Fatalf("failed to unmarshal key_id: %v", err)
	}
	if keyID != "key-123" {
		t.Fatalf("expected key_id key-123, got %q", keyID)
	}

	var sbom map[string]any
	if err := json.Unmarshal(payload["sbom"], &sbom); err != nil {
		t.Fatalf("failed to unmarshal sbom: %v", err)
	}
	if sbom["bomFormat"] != "CycloneDX" {
		t.Fatalf("unexpected sbom payload: %#v", sbom)
	}

	outputPath := signedOutputPath(sbomPath)
	written, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("expected signed output file: %v", err)
	}
	if string(written) != `{"bomFormat":"CycloneDX","signature":"abc123"}` {
		t.Fatalf("unexpected signed output: %q", string(written))
	}
}

func TestRun_V2Verify_JSON(t *testing.T) {
	tmpDir := t.TempDir()
	sbomPath := writeTempFile(t, tmpDir, "test.json", `{"bomFormat":"CycloneDX"}`)

	var gotPath string
	var gotContentType string
	var gotBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")

		var err error
		gotBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed reading body: %v", err)
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"verified_v2":true}`))
	}))
	defer server.Close()

	opts := RunOptions{
		SecureSBOMAPIURL: server.URL,
		SecureSBOMAPIKey: "api-key-123",
		Action:           ActionVerify,
		SBOMFilePath:     sbomPath,
		UseV1API:         false,
	}

	err := run(opts, server.Client())
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	if gotPath != "/"+verifyPathV2 {
		t.Fatalf("expected path %q, got %q", "/"+verifyPathV2, gotPath)
	}
	if gotContentType != "application/json" {
		t.Fatalf("expected application/json, got %q", gotContentType)
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(gotBody, &payload); err != nil {
		t.Fatalf("failed to unmarshal request: %v", err)
	}
	if len(payload["sbom"]) == 0 {
		t.Fatal("expected sbom field in request body")
	}
}

func TestRun_SignDigest_JSON(t *testing.T) {
	var gotPath string
	var gotContentType string
	var gotBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")

		var err error
		gotBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed reading body: %v", err)
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"signature":"abc123"}`))
	}))
	defer server.Close()

	opts := RunOptions{
		SecureSBOMAPIURL: server.URL,
		SecureSBOMAPIKey: "api-key-123",
		SigningKeyID:     "key-123",
		Action:           ActionSignDigest,
		Digest:           "Zm9vYmFy",
	}

	err := run(opts, server.Client())
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	if gotPath != "/"+signDigestPathV1 {
		t.Fatalf("expected path %q, got %q", "/"+signDigestPathV1, gotPath)
	}
	if gotContentType != "application/json" {
		t.Fatalf("expected application/json, got %q", gotContentType)
	}

	var payload map[string]string
	if err := json.Unmarshal(gotBody, &payload); err != nil {
		t.Fatalf("failed to unmarshal request: %v", err)
	}
	if payload["digest"] != "Zm9vYmFy" {
		t.Fatalf("expected digest, got %q", payload["digest"])
	}
	if payload["key_id"] != "key-123" {
		t.Fatalf("expected key_id, got %q", payload["key_id"])
	}
}

func TestRun_Non200Response(t *testing.T) {
	tmpDir := t.TempDir()
	sbomPath := writeTempFile(t, tmpDir, "test.json", `{"bomFormat":"CycloneDX"}`)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request from api", http.StatusBadRequest)
	}))
	defer server.Close()

	opts := RunOptions{
		SecureSBOMAPIURL: server.URL,
		SecureSBOMAPIKey: "api-key-123",
		SigningKeyID:     "key-123",
		Action:           ActionSign,
		SBOMFilePath:     sbomPath,
		UseV1API:         false,
	}

	err := run(opts, server.Client())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "API error (400)") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(err.Error(), "bad request from api") {
		t.Fatalf("expected API body in error, got: %v", err)
	}
}

func TestRun_NetworkFailure(t *testing.T) {
	tmpDir := t.TempDir()
	sbomPath := writeTempFile(t, tmpDir, "test.json", `{"bomFormat":"CycloneDX"}`)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	serverURL := server.URL
	server.Close()

	opts := RunOptions{
		SecureSBOMAPIURL: serverURL,
		SecureSBOMAPIKey: "api-key-123",
		SigningKeyID:     "key-123",
		Action:           ActionSign,
		SBOMFilePath:     sbomPath,
		UseV1API:         false,
	}

	err := run(opts, http.DefaultClient)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "request failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}
