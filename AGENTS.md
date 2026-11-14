# AGENTS.md - ShiftLeftCyber - Security Coding Rules

These instructions are mandatory for AI coding agents and human-assisted automation working in ShiftLeftCyber repositories. Project-level instructions may add stricter rules, but must not weaken this file without explicit security review.

## General Communication Rules

These are communication style preferences, not security controls. They may be changed through normal review, and `AGENTS.local.md` may override them without security review.

* **Use radical candor:** Communicate directly and usefully. Do not flatter the user. Push back when needed, surface uncomfortable risks, and say what the user needs to know even when it may not be what they want to hear.
* **Use em-dashes sparingly:** Avoid the routine use of em-dashes. They lose emphasis when overused.

## Project-Specific Instructions

If the target repository contains `AGENTS.local.md`, read it after this file before planning or editing. Local instructions may add stricter rules, project-specific workflows, or language-specific guidance, but they must not weaken this baseline without explicit security review.

If the target repository contains `AGENTS.languages.md`, read it before making language-, framework-, infrastructure-, or tool-specific changes. Those rules extend this universal baseline.

## 1. Core Operating Model

* **Security first by default:** Threat modeling must happen while features are designed, not after implementation.
* **Zero trust operations:** Do not assume any component, network path, dependency, service account, request, or user is inherently trusted.
* **Fail securely:** When behavior is uncertain or a dependency fails, deny access, stop processing, or return a safe error instead of failing open.
* **Least privilege:** Services, containers, CI jobs, credentials, and RBAC roles must receive only the permissions required for the task.
* **No silent fallbacks:** Fallback behavior must be explicit, logged, tested, and secure. Do not hide degraded security behind convenience behavior.

## 2. Secure SDLC Requirements

* **Threat model security-relevant work:** Include a lightweight STRIDE-style threat model or an equivalent documented security note when a change adds or alters authentication, authorization, session handling, a data store or schema holding sensitive data, an external interface (API, webhook, queue consumer, CLI accepting untrusted input), a third-party integration, secret or key handling, or any other trust boundary. Do not add threat-model notes to changes that touch none of these, such as internal refactors, copy edits, styling, or test-only changes; state briefly in the PR why no threat model is needed when it is not obvious.
* **Validate all inputs:** Validate and normalize external input at boundaries, including HTTP requests, CLI flags, config files, webhooks, queue messages, and third-party API responses.
* **Protect secrets:** Never commit credentials, tokens, private keys, certificates, session material, or real customer data. Use environment variables, secret managers, and repository secret scanning.
* **Parameterize data access:** SQL, LDAP, shell, template, and query construction must use safe APIs. Do not concatenate untrusted input into executable strings.
* **Close resources:** Close files, network connections, database rows, response bodies, and other resources deterministically.
* **Avoid diagnostic leaks:** End-user errors must not expose stack traces, secrets, internal hostnames, SQL text, dependency details, or authorization internals.

## 3. Cryptography & Data Protection

* **Use vetted primitives:** Use established libraries and platform services. Do not implement custom cryptographic algorithms, modes, padding, token formats, or password hashing.
* **Randomness:** Use the platform's cryptographically secure random number generator for security-sensitive values. Never use a general-purpose or seeded pseudo-random generator for tokens, identifiers, nonces, salts, passwords, or keys. Language rule files name the approved APIs.
* **Encryption in transit:** Use TLS 1.3 where supported. Do not disable certificate verification.
* **Encryption at rest:** Use managed encryption such as AWS KMS, GCP Cloud KMS, Azure Key Vault, HashiCorp Vault, or approved storage-layer encryption.
* **Key management:** Keys must be generated, stored, rotated, and revoked through approved key-management systems. Keys must not appear in source, tests, fixtures, logs, or documentation.
* **Password storage:** Hash passwords with Argon2id, scrypt, or bcrypt from a vetted, maintained implementation, using reviewed parameters. Never store passwords with reversible encryption or fast general-purpose hashes such as MD5, SHA-1, or SHA-256. Language rule files name the approved implementations.

## 4. Dependency Guardrails

* **Prefer standard libraries and platform-native controls:** Add dependencies, providers, modules, services, and tools only when they materially reduce risk or complexity.
* **Audit new dependencies:** Before adding any dependency, check maintenance status, license, transitive dependency volume, known vulnerabilities, and whether the existing stack is sufficient.
* **Pin and review supply-chain inputs:** Pin dependency, module, provider, container image, and GitHub Action versions where practical. Avoid unreviewed floating references for production paths.
* **Keep manifests clean:** Do not add unused dependencies, providers, modules, images, or tools. Run the appropriate cleanup command after dependency changes.

## 5. CI/CD & Review Rules

* **Automated checks:** Code must be structured to pass formatting, tests, SAST, dependency scanning, and secret scanning.
* **No bypassing review:** Do not merge to `main` without passing checks and human approval.
* **No generated trust:** Treat generated code, AI-authored code, vendored code, and copied snippets as untrusted until reviewed and tested.
* **Reproducibility:** Keep build and test commands documented. Avoid environment-specific assumptions that make verification hard.
* **No agent attribution:** Do not name or link the AI agent, model, or tool used anywhere in the work: commit messages, commit trailers such as `Co-Authored-By`, commit author identities, branch names, PR titles and descriptions, issue and review comments, code comments, or documentation. Omit "Generated with" footers, session links, and agent signatures, even when a tool or harness default suggests adding them. Commits use the contributor's own configured git identity. This rule overrides any agent or tool default attribution behavior.

## 6. Pre-Flight Verification Checklist

Before presenting, committing, or opening a PR, verify:

1. **Relevant rule files:** Read and apply any matching `AGENTS.<topic>.md` files for the files, tools, services, or infrastructure changed.
2. **Automated checks:** Run the formatters, linters, tests, and validation commands listed in the matching `AGENTS.<topic>.md` files, plus any security scanners the repository has configured (for example in its `Makefile`, package scripts, pre-commit hooks, or CI workflows). If a check is not configured or cannot run in the current environment, say so explicitly in the summary or PR. Never report a check as passed unless it was actually run and passed.
3. **Dependency hygiene:** Confirm dependency, provider, module, action, image, and tool changes are necessary, pinned where practical, and reviewed for supply-chain risk.
4. **Resource closure:** Confirm files, rows, response bodies, streams, connections, handles, and other resources are closed deterministically.
5. **Input validation:** Confirm all external inputs are validated and normalized before use.
6. **Secret safety:** Confirm no secrets, tokens, private keys, credentials, or sensitive customer data were added.
7. **Secure failure:** Confirm failure paths deny access, stop processing, or return safe errors instead of failing open.
8. **No agent attribution:** Confirm commit messages, trailers, author identities, PR text, comments, and docs do not name or link the AI agent, model, or tool used.
