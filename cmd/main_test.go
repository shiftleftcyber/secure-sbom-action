package main

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

type mockRoundTripper struct {
	status int
	body   string
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: m.status,
		Body:       io.NopCloser(bytes.NewBufferString(m.body)),
	}, nil
}

func writeTempSBOM(t *testing.T, content string) string {
	f, err := os.CreateTemp("", "*.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(content)
	_ = f.Close()
	return f.Name()
}

func TestRun_SuccessfulSign(t *testing.T) {
	sbom := writeTempSBOM(t, `{"bomFormat":"CycloneDX"}`)
	defer func() {
		_ = os.Remove(sbom)
	}()

	client := &http.Client{
		Transport: &mockRoundTripper{status: 200, body: `{"signed":true}`},
	}

	err := run(sbom, "test-key", "test-api-key", "", "sign", client)
	if err != nil {
		t.Errorf("expected success, got error: %v", err)
	}

	signed := sbom[:len(sbom)-len(filepath.Ext(sbom))] + ".signed" + filepath.Ext(sbom)
	if _, err := os.Stat(signed); err != nil {
		t.Errorf("signed file not found: %v", err)
	}
	_ = os.Remove(signed)
}

func TestRun_MissingFile(t *testing.T) {
	client := &http.Client{Transport: &mockRoundTripper{}}
	err := run("missing.json", "key", "key", "", "sign", client)
	if err == nil || err.Error() == "" {
		t.Errorf("expected error for missing file")
	}
}

func TestRun_InvalidAction(t *testing.T) {
	sbom := writeTempSBOM(t, `{}`)
	defer func() {
		_ = os.Remove(sbom)
	}()

	client := &http.Client{}
	err := run(sbom, "key", "key", "", "delete", client)
	if err == nil || err.Error() == "" {
		t.Errorf("expected error for invalid action")
	}
}
