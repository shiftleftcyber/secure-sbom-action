# GitHub Actions Rules

Apply these rules when editing `.github/workflows/*.yml`, `.github/workflows/*.yaml`, custom actions, reusable workflows, or CI/CD scripts executed by GitHub Actions.

## Critical Rules

* **Use least-privilege permissions:** Set top-level `permissions: read-all` or explicit minimal permissions. Grant write scopes only at the job level where required.
* **Keep untrusted PRs unprivileged:** Pull request jobs that run untrusted code must not receive write tokens, deployment credentials, package publish tokens, cloud credentials, or production secrets.
* **Pin third-party actions:** Pin external actions and reusable workflows to full commit SHAs for production or security-sensitive workflows. Review ownership and maintenance before adding new actions.
* **Use OIDC when possible:** Prefer GitHub OIDC federation with short-lived cloud credentials over long-lived cloud keys. Restrict trust by repo, branch, environment, workflow, and audience.
* **Protect secrets and artifacts:** Do not echo secrets, dump environments, upload `.env` files, private keys, Terraform state, generated credentials, or sensitive logs as artifacts or caches.
* **Treat GitHub context as untrusted:** Validate and quote branch names, tags, titles, comments, labels, workflow inputs, paths, and matrix values before using them in shell commands.
* **Use `pull_request_target` sparingly:** Do not check out or execute untrusted pull request code in `pull_request_target`; use it only for trusted metadata tasks.
* **Gate privileged jobs:** Deployments, releases, signing, package publishing, image pushes, and Terraform applies must run only from trusted refs, protected environments, or manual approvals.
* **Limit checkout credentials:** Set `persist-credentials: false` for `actions/checkout` unless later steps need the repository token for authenticated Git operations.
* **Use shell safety defaults:** Prefer Bash steps with `set -euo pipefail`, quoted variables, and controlled inputs. Avoid building commands from untrusted strings.
* **Constrain deployments:** Use `environment`, `timeout-minutes`, and `concurrency` for deployment, release, signing, and Terraform jobs.
* **Separate build from publish:** Build and test jobs should not have publish credentials. Publish jobs should consume reviewed artifacts from trusted branches or tags.

## GitHub Actions Verification

Before presenting, committing, or opening a PR for GitHub Actions changes:

1. Validate workflow YAML syntax with `actionlint` or an available linter when available.
2. Review every `permissions` block for least privilege.
3. Confirm third-party actions and reusable workflows are pinned appropriately.
4. Confirm secrets are not exposed to untrusted pull request code, logs, artifacts, or caches.
5. Confirm deployment, release, publish, signing, and infrastructure jobs are gated by trusted refs, environments, or approvals.
6. Confirm shell steps quote untrusted inputs and avoid direct interpolation of GitHub context values.
