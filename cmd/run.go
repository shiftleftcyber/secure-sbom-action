package main

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"encoding/json"
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

const (
	defaultGatewayURL = "https://secure-sbom-api-prod-gateway-dhncnyq8.uc.gateway.dev"
	signPath          = "api/v1/sbom/sign"
	verifyPath        = "api/v1/sbom/verify"
	signPathV2 		  = "api/v2/sbom/sign"
	verifyPathV2      = "api/v2/sbom/verify"
	signDigestPathV1      = "api/v1/digest/sign"
)

func run(opts RunOptions, client HTTPClient) error {
	if client == nil {
		client = http.DefaultClient
	}

	endpoint, err := buildEndpoint(opts)
	if err != nil {
		return err
	}

	req, err := buildRequest(opts, endpoint)
	if err != nil {
		return err
	}

	req.Header.Set("x-api-key", opts.SecureSBOMAPIKey)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
	}

	return handleResponse(opts, body)
}

func buildEndpoint(opts RunOptions) (string, error) {

	base := strings.TrimRight(opts.SecureSBOMAPIURL, "/")

	switch opts.Action {

	case ActionSign, ActionSignSBOM:
		if opts.UseV1API {
			return base + "/" + signPath, nil
		}
		return base + "/" + signPathV2, nil

	case ActionVerify, ActionVerifySBOM:
		if opts.UseV1API {
			return base + "/" + verifyPath, nil
		}
		return base + "/" + verifyPathV2, nil

	case ActionSignDigest:
		return base + "/" + signDigestPathV1, nil

	default:
		return "", fmt.Errorf("unsupported action: %s", opts.Action)
	}
}

func buildRequest(opts RunOptions, endpoint string) (*http.Request, error) {

	switch opts.Action {

	case ActionSignDigest:
		return buildDigestRequest(opts, endpoint)

	case ActionSign, ActionSignSBOM, ActionVerify, ActionVerifySBOM:

		if opts.UseV1API {
			return buildMultipartSBOMRequest(opts, endpoint)
		}

		return buildJSONSBOMRequest(opts, endpoint)

	default:
		return nil, fmt.Errorf("unsupported action: %s", opts.Action)
	}
}

func buildMultipartSBOMRequest(opts RunOptions, endpoint string) (*http.Request, error) {

	if _, err := os.Stat(opts.SBOMFilePath); err != nil {
		return nil, fmt.Errorf("missing sbom file: %w", err)
	}

	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)

	if opts.SigningKeyID != "" {
		_ = writer.WriteField("key_id", opts.SigningKeyID)
	}

	fileWriter, err := writer.CreateFormFile("sbom", filepath.Base(opts.SBOMFilePath))
	if err != nil {
		return nil, fmt.Errorf("failed to create form file: %w", err)
	}

	fileHandle, err := os.Open(opts.SBOMFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sbom file: %w", err)
	}
	defer fileHandle.Close()

	if _, err := io.Copy(fileWriter, fileHandle); err != nil {
		return nil, fmt.Errorf("failed to copy file contents: %w", err)
	}

	writer.Close()

	req, err := http.NewRequest("POST", endpoint, &requestBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	return req, nil
}

func buildJSONSBOMRequest(opts RunOptions, endpoint string) (*http.Request, error) {

	data, err := os.ReadFile(opts.SBOMFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read sbom file: %w", err)
	}

	payload := map[string]interface{}{
		"sbom": json.RawMessage(data),
	}

	if opts.SigningKeyID != "" {
		payload["key_id"] = opts.SigningKeyID
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	return req, nil
}

func buildDigestRequest(opts RunOptions, endpoint string) (*http.Request, error) {

	payload := map[string]string{
		"digest": opts.Digest,
		"key_id": opts.SigningKeyID,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	return req, nil
}

func handleResponse(opts RunOptions, body []byte) error {

	switch opts.Action {

	case ActionSign, ActionSignSBOM:

		ext := filepath.Ext(opts.SBOMFilePath)
		base := opts.SBOMFilePath[:len(opts.SBOMFilePath)-len(ext)]
		output := base + ".signed" + ext

		if err := os.WriteFile(output, body, 0644); err != nil {
			return fmt.Errorf("failed to write signed file: %w", err)
		}

		fmt.Println("SBOM signed successfully →", output)

	case ActionVerify, ActionVerifySBOM:

		fmt.Println("Verification output:")
		fmt.Println(string(body))

	case ActionSignDigest:

		fmt.Println("Digest signed successfully:")
		fmt.Println(string(body))

	}

	return nil
}