package main

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

const (
	defaultGatewayURL = "https://secure-sbom-api-prod-gateway-dhncnyq8.uc.gateway.dev"
	signPath          = "api/v1/sbom/sign"
	verifyPath        = "api/v1/sbom/verify"
)

func run(sbomFile, keyID, apiKey, gateway, action string, client *http.Client) error {
	if _, err := os.Stat(sbomFile); err != nil {
		return fmt.Errorf("missing sbom file: %w", err)
	}

	if keyID == "" || apiKey == "" {
		return fmt.Errorf("missing required key or api key")
	}
	if gateway == "" {
		gateway = defaultGatewayURL
	}

	var endpoint string
	var fileKey string
	switch action {
	case "sign":
		endpoint = fmt.Sprintf("%s/%s", gateway, signPath)
		fileKey = "sbom"
	case "verify":
		endpoint = fmt.Sprintf("%s/%s", gateway, verifyPath)
		fileKey = "sbom"
	default:
		endpoint = fmt.Sprintf("%s/%s", gateway, signPath)
		fileKey = "sbom"
	}

	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)
	_ = writer.WriteField("key_id", keyID)

	fileWriter, err := writer.CreateFormFile(fileKey, filepath.Base(sbomFile))
	if err != nil {
		return fmt.Errorf("failed to create form file: %w", err)
	}

	fileHandle, err := os.Open(sbomFile)
	if err != nil {
		return fmt.Errorf("failed to open sbom file: %w", err)
	}
	defer func() {
		_ = fileHandle.Close()
	}()

	if _, err := io.Copy(fileWriter, fileHandle); err != nil {
		return fmt.Errorf("failed to copy file contents: %w", err)
	}

	_ = writer.Close()

	req, err := http.NewRequest("POST", endpoint, &requestBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("x-api-key", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
	}

	if action == "sign" {
		ext := filepath.Ext(sbomFile)
		base := sbomFile[:len(sbomFile)-len(ext)]
		output := base + ".signed" + ext
		if err := os.WriteFile(output, body, 0644); err != nil {
			return fmt.Errorf("failed to write signed file: %w", err)
		}
		fmt.Println("SBOM signed successfully →", output)
	} else {
		fmt.Println("Verification output:", string(body))
	}

	return nil
}

func main() {
	err := run(
		os.Getenv("SBOM_FILE"),
		os.Getenv("KEY_ID"),
		os.Getenv("API_KEY"),
		os.Getenv("API_GATEWAY"),
		os.Getenv("SECURE_SBOM_ACTION"),
		http.DefaultClient,
	)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}
