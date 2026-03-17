package main

import (
	"bytes"
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

func TestRun_V1Sign_MultipartAndWritesSignedFile(t *testing.T) {
	fs := NewMockFS()
	fs.files["test.json"] = []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5"}`)

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
		SBOMFilePath:     "test.json",
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

	written, err := fs.ReadFile("test.signed.json")
	if err != nil {
		t.Fatalf("expected signed output file: %v", err)
	}
	if string(written) != `{"signed":true}` {
		t.Fatalf("unexpected signed output: %q", string(written))
	}
}
