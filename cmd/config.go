package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
)

type Action string

const (
	ActionSignSBOM   Action = "sign_sbom"
	ActionSign       Action = "sign"
	ActionVerifySBOM Action = "verify_sbom"
	ActionVerify     Action = "verify"
	ActionSignDigest Action = "sign_digest"
)

type RunOptions struct {
	SecureSBOMAPIKey string
	SecureSBOMAPIURL string
	SigningKeyID     string
	Action           Action
	SBOMFilePath     string
	Digest           string
	DigestHash       string
	UseV1API         bool
}

func (o RunOptions) APIVersion() string {
	if o.UseV1API {
		return "v1"
	}
	return "v2"
}

type EnvResolver struct {
	logger func(format string, args ...any)
	getenv func(string) string
}

func NewEnvResolver(logger *log.Logger) *EnvResolver {
	logFn := func(string, ...any) {}
	if logger != nil {
		logFn = logger.Printf
	}

	return &EnvResolver{
		logger: logFn,
		getenv: os.Getenv,
	}
}

func LoadRunOptionsFromEnv(logger *log.Logger) (*RunOptions, error) {
	resolver := NewEnvResolver(logger)

	var opts RunOptions
	var errs []string

	opts.SecureSBOMAPIKey = resolver.Require(
		"SECURE_SBOM_API_KEY",
		"API_KEY",
		&errs,
	)

	opts.SecureSBOMAPIURL = resolver.Optional(
		"SECURE_SBOM_API_URL",
		"API_URL",
	)
	if opts.SecureSBOMAPIURL == "" {
		opts.SecureSBOMAPIURL = defaultGatewayURL
	}

	opts.Action = Action(resolver.Require(
		"SECURE_SBOM_ACTION",
		"ACTION",
		&errs,
	))

	if opts.Action != "" && !opts.Action.IsValid() {
		errs = append(errs,
			fmt.Sprintf("invalid action %q: must be one of %s", opts.Action, strings.Join(validActionStrings(), ", ")),
		)
	}

	if opts.Action.RequiresSigningKeyID() {
		opts.SigningKeyID = resolver.Require(
			"SECURE_SBOM_SIGNING_KEY_ID",
			"KEY_ID",
			&errs,
		)
	}

	if opts.Action.RequiresSBOMFile() {
		opts.SBOMFilePath = resolver.Require(
			"SBOM_FILE",
			"",
			&errs,
		)
	}

	if opts.Action.RequiresDigest() {
		opts.Digest = resolver.Require(
			"DIGEST",
			"",
			&errs,
		)
	}

	if opts.Action.RequiresDigest() {
		opts.DigestHash = resolver.Require(
			"DIGEST_HASH_ALGORITHM",
			"",
			&errs,
		)
	}

	opts.UseV1API = resolver.OptionalBool(
		"SECURE_SBOM_USE_V1_API",
		false,
		&errs,
	)

	if len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}

	return &opts, nil
}

func (r *EnvResolver) Optional(newName string, oldName string) string {
	if v := strings.TrimSpace(r.getenv(newName)); v != "" {
		return v
	}

	if oldName != "" {
		if v := strings.TrimSpace(r.getenv(oldName)); v != "" {
			r.logger("WARNING: environment variable %s is deprecated; use %s instead", oldName, newName)
			return v
		}
	}

	return ""
}

func (r *EnvResolver) OptionalBool(name string, defaultVal bool, errs *[]string) bool {
	val := r.Optional(name, "")

	if val == "" {
		return defaultVal
	}

	switch strings.ToLower(strings.TrimSpace(val)) {
	case "true", "1", "yes", "y":
		return true
	case "false", "0", "no", "n":
		return false
	default:
		if errs != nil {
			*errs = append(*errs,
				fmt.Sprintf("invalid boolean value for %s: %q (expected true/false)", name, val),
			)
		}
		return defaultVal
	}
}

func (r *EnvResolver) Require(newName string, oldName string, errs *[]string) string {
	v := r.Optional(newName, oldName)
	if v != "" {
		return v
	}

	if oldName != "" {
		*errs = append(*errs, fmt.Sprintf("missing required environment variable %s (legacy: %s)", newName, oldName))
	} else {
		*errs = append(*errs, fmt.Sprintf("missing required environment variable %s", newName))
	}

	return ""
}

func (a Action) IsValid() bool {
	switch a {
	case ActionSignSBOM, ActionSign, ActionVerifySBOM, ActionVerify, ActionSignDigest:
		return true
	default:
		return false
	}
}

func (a Action) RequiresSBOMFile() bool {
	switch a {
	case ActionSignSBOM, ActionSign, ActionVerifySBOM, ActionVerify:
		return true
	default:
		return false
	}
}

func (a Action) RequiresDigest() bool {
	return a == ActionSignDigest
}

func (a Action) RequiresSigningKeyID() bool {
	switch a {
	case ActionSignSBOM, ActionSign, ActionSignDigest, ActionVerifySBOM, ActionVerify:
		return true
	default:
		return false
	}
}

func validActionStrings() []string {
	return []string{
		string(ActionSignSBOM),
		string(ActionSign),
		string(ActionVerifySBOM),
		string(ActionVerify),
		string(ActionSignDigest),
	}
}
