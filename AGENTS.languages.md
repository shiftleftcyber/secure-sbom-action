# AGENTS.languages.md - Rule Index

These instructions extend the universal `AGENTS.md` baseline. Before making language-, framework-, infrastructure-, or tool-specific changes, read the relevant `AGENTS.<topic>.md` rule files.

## Rule Files

* **Go:** read `AGENTS.go.md` when Go files, Go modules, or Go services are present.
* **TypeScript:** read `AGENTS.typescript.md` when TypeScript, JavaScript, Node.js, frontend, or package-manager files are present.
* **Terraform:** read `AGENTS.terraform.md` when Terraform files, OpenTofu-compatible modules, provider configuration, backend configuration, infrastructure modules, or environment overlays are present.
* **GitHub Actions:** read `AGENTS.github-actions.md` when editing `.github/workflows/*.yml`, `.github/workflows/*.yaml`, custom actions, reusable workflows, or CI/CD scripts executed by GitHub Actions.

Projects install only the rule files they select, so some of the files above may be absent. If you are changing files covered by a rule file that is not installed in this repository, tell the user so they can re-run the shared installer with that language selected; until then, apply the universal baseline.

Project-specific `AGENTS.local.md` rules may require additional rule files. Local rules may add stricter requirements, but must not weaken this baseline without explicit security review.
