package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func createTempSBOM(t *testing.T) string {
	t.Helper()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "sbom.json")

	data := `{"bomFormat":"CycloneDX","specVersion":"1.5"}`

	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	return path
}

func newOptions() RunOptions {
	return RunOptions{
		SecureSBOMAPIURL: "https://example.com",
		SecureSBOMAPIKey: "apikey",
		SigningKeyID:     "key123",
	}
}

func TestBuildEndpoint(t *testing.T) {

	tests := []struct {
		name string
		opts RunOptions
		want string
	}{
		{
			"v1 sign",
			RunOptions{SecureSBOMAPIURL: "https://example.com", Action: ActionSign, UseV1API: true},
			"https://example.com/" + signPath,
		},
		{
			"v2 sign",
			RunOptions{SecureSBOMAPIURL: "https://example.com", Action: ActionSign, UseV1API: false},
			"https://example.com/" + signPathV2,
		},
		{
			"v1 verify",
			RunOptions{SecureSBOMAPIURL: "https://example.com", Action: ActionVerify, UseV1API: true},
			"https://example.com/" + verifyPath,
		},
		{
			"v2 verify",
			RunOptions{SecureSBOMAPIURL: "https://example.com", Action: ActionVerify},
			"https://example.com/" + verifyPathV2,
		},
		{
			"digest",
			RunOptions{SecureSBOMAPIURL: "https://example.com", Action: ActionSignDigest},
			"https://example.com/" + signDigestPathV1,
		},
	}

	for _, tt := range tests {

		endpoint, err := buildEndpoint(tt.opts)
		if err != nil {
			t.Fatal(err)
		}

		if endpoint != tt.want {
			t.Fatalf("expected %s got %s", tt.want, endpoint)
		}
	}
}

func TestBuildMultipartSBOMRequest(t *testing.T) {

	sbom := createTempSBOM(t)

	opts := newOptions()
	opts.SBOMFilePath = sbom

	req, err := buildMultipartSBOMRequest(opts, "http://example.com")
	if err != nil {
		t.Fatal(err)
	}

	if req.Method != http.MethodPost {
		t.Fatal("expected POST")
	}

	ct := req.Header.Get("Content-Type")
	if !strings.Contains(ct, "multipart/form-data") {
		t.Fatalf("unexpected content-type %s", ct)
	}

	body, _ := io.ReadAll(req.Body)

	if !bytes.Contains(body, []byte("key123")) {
		t.Fatal("missing key_id field")
	}

	if !bytes.Contains(body, []byte("CycloneDX")) {
		t.Fatal("sbom contents missing")
	}
}

func TestBuildJSONSBOMRequest(t *testing.T) {

	sbom := createTempSBOM(t)

	opts := newOptions()
	opts.SBOMFilePath = sbom

	req, err := buildJSONSBOMRequest(opts, "http://example.com")
	if err != nil {
		t.Fatal(err)
	}

	if req.Header.Get("Content-Type") != "application/json" {
		t.Fatal("expected application/json")
	}

	body, _ := io.ReadAll(req.Body)

	var payload map[string]interface{}

	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}

	if payload["key_id"] != "key123" {
		t.Fatal("key_id missing")
	}

	if payload["sbom"] == nil {
		t.Fatal("sbom missing")
	}
}

func TestBuildDigestRequest(t *testing.T) {

	opts := newOptions()
	opts.Action = ActionSignDigest
	opts.Digest = "abcd123"

	req, err := buildDigestRequest(opts, "http://example.com")
	if err != nil {
		t.Fatal(err)
	}

	body, _ := io.ReadAll(req.Body)

	var payload map[string]string

	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}

	if payload["digest_b64"] != "abcd123" {
		t.Fatal("digest missing")
	}

	if payload["key_id"] != "key123" {
		t.Fatal("key_id missing")
	}
}

func TestBuildRequestDispatch(t *testing.T) {

	sbom := createTempSBOM(t)

	tests := []RunOptions{
		{
			Action:           ActionSign,
			UseV1API:         true,
			SBOMFilePath:     sbom,
			SigningKeyID:     "key",
			SecureSBOMAPIKey: "key",
		},
		{
			Action:           ActionSign,
			UseV1API:         false,
			SBOMFilePath:     sbom,
			SigningKeyID:     "key",
			SecureSBOMAPIKey: "key",
		},
		{
			Action:           ActionSignDigest,
			Digest:           "abc",
			SigningKeyID:     "key",
			SecureSBOMAPIKey: "key",
		},
	}

	for _, opts := range tests {

		_, err := buildRequest(opts, "http://example.com")
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestHandleResponseSign_V1(t *testing.T) {
	sbom := createTempSBOM(t)

	opts := newOptions()
	opts.Action = ActionSign
	opts.SBOMFilePath = sbom
	opts.UseV1API = true

	body := []byte(`signed`)

	if err := handleResponse(opts, body); err != nil {
		t.Fatal(err)
	}

	out := signedOutputPath(sbom)

	written, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("signed file not created: %v", err)
	}

	if string(written) != "signed" {
		t.Fatalf("unexpected signed file contents: %q", string(written))
	}
}

func TestHandleResponseSign_V2(t *testing.T) {
	sbom := createTempSBOM(t)

	opts := newOptions()
	opts.Action = ActionSign
	opts.SBOMFilePath = sbom
	opts.UseV1API = false

	body := []byte(`{"signed_sbom":{"bomFormat":"CycloneDX"}}`)

	if err := handleResponse(opts, body); err != nil {
		t.Fatal(err)
	}

	out := signedOutputPath(sbom)

	written, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("signed file not created: %v", err)
	}

	if string(written) != `{"bomFormat":"CycloneDX"}` {
		t.Fatalf("unexpected signed file contents: %q", string(written))
	}
}

func TestHandleResponseVerify(t *testing.T) {

	opts := newOptions()
	opts.Action = ActionVerify

	err := handleResponse(opts, []byte(`ok`))
	if err != nil {
		t.Fatal(err)
	}
}

type fakeRoundTripper struct{}

func (f fakeRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {

	body := io.NopCloser(bytes.NewBufferString("signed"))

	return &http.Response{
		StatusCode: 200,
		Body:       body,
		Header:     make(http.Header),
	}, nil
}

func TestRun(t *testing.T) {
	sbom := createTempSBOM(t)

	opts := newOptions()
	opts.Action = ActionSign
	opts.SBOMFilePath = sbom
	opts.UseV1API = true

	client := &http.Client{
		Transport: fakeRoundTripper{},
	}

	if err := run(opts, client); err != nil {
		t.Fatal(err)
	}

	out := signedOutputPath(sbom)

	written, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("signed file not created: %v", err)
	}

	if string(written) != "signed" {
		t.Fatalf("unexpected signed file contents: %q", string(written))
	}
}

type fakeRoundTripperV2 struct{}

func (f fakeRoundTripperV2) RoundTrip(r *http.Request) (*http.Response, error) {
	body := io.NopCloser(bytes.NewBufferString(`{"signed_sbom":{"bomFormat":"CycloneDX"}}`))

	return &http.Response{
		StatusCode: 200,
		Body:       body,
		Header:     make(http.Header),
	}, nil
}

func TestRun_V2(t *testing.T) {
	sbom := createTempSBOM(t)

	opts := newOptions()
	opts.Action = ActionSign
	opts.SBOMFilePath = sbom
	opts.UseV1API = false

	client := &http.Client{
		Transport: fakeRoundTripperV2{},
	}

	if err := run(opts, client); err != nil {
		t.Fatal(err)
	}

	out := signedOutputPath(sbom)

	written, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("signed file not created: %v", err)
	}

	if string(written) != `{"bomFormat":"CycloneDX"}` {
		t.Fatalf("unexpected signed file contents: %q", string(written))
	}
}
