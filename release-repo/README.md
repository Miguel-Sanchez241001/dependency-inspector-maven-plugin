# dep-inspector-release

Private repository that handles GPG signing and Maven Central publication for
`dependency-inspector-maven-plugin`. The plugin source lives in the public repo
`Miguel-Sanchez241001/dependency-inspector-maven-plugin`; this repo holds only the
CI secrets and the deploy workflow.

---

## Architecture

```
Plugin repo (public)                      Release repo (private)
─────────────────────                     ──────────────────────
PR merged to main                         repository_dispatch event
  → ci.yml: test + smoke                    → deploy.yml: sign + publish
  → trigger-release job                         ↑
      → fires repository_dispatch ──────────────┘
```

This separation ensures that:
- Contributors can see test output in the public repo
- GPG keys and Sonatype credentials never touch a public workflow log
- The plugin repo PAT used in the release repo has minimal scope

---

## Required Secrets

### Plugin repo (`dependency-inspector-maven-plugin`)

| Secret | Value |
|--------|-------|
| `RELEASE_REPO_PAT` | Fine-grained PAT with **Contents: write** permission on this release repo |

### Release repo (this repo)

| Secret | Value |
|--------|-------|
| `GPG_PRIVATE_KEY` | ASCII-armored GPG private key (`gpg --armor --export-secret-keys FINGERPRINT`) |
| `SONATYPE_USERNAME` | Token username from `central.sonatype.com` → User token |
| `SONATYPE_PASSWORD` | Token password from `central.sonatype.com` → User token |
| `PLUGIN_REPO_PAT` | Fine-grained PAT with **Contents: write** on the plugin repo (for tagging + pushing next SNAPSHOT) |

---

## Creating the Secrets

### GPG key
```bash
# Export your key (fingerprint from memory: 2B2BD5A161F54317896BFD385E9FE22440B6B8E8)
gpg --armor --export-secret-keys 2B2BD5A161F54317896BFD385E9FE22440B6B8E8
```
Paste the full output (including `-----BEGIN PGP PRIVATE KEY BLOCK-----`) into the
`GPG_PRIVATE_KEY` secret.

### Sonatype tokens
1. Log in at <https://central.sonatype.com>
2. Go to **Account → User Token**
3. Generate a new token
4. Copy the username and password into `SONATYPE_USERNAME` / `SONATYPE_PASSWORD`

### Fine-grained PATs
1. Go to GitHub → Settings → Developer settings → Fine-grained tokens
2. **RELEASE_REPO_PAT** (for plugin repo):
   - Resource owner: `Miguel-Sanchez241001`
   - Repository: `dep-inspector-release`
   - Permissions: **Contents: write**
3. **PLUGIN_REPO_PAT** (for this release repo):
   - Resource owner: `Miguel-Sanchez241001`
   - Repository: `dependency-inspector-maven-plugin`
   - Permissions: **Contents: write**

---

## How a Release Happens

### Automatic (on merge to main)
1. A PR is merged to `main` in the plugin repo
2. `ci.yml` runs `test` and `smoke` jobs
3. On success, `trigger-release` fires a `repository_dispatch` with the commit SHA
   and current version (e.g. `1.0.1-SNAPSHOT`)
4. `deploy.yml` in this repo:
   - Checks out the plugin repo at that exact SHA
   - Strips `-SNAPSHOT` → computes release version (`1.0.1`)
   - Sets version in pom.xml, builds, signs, deploys to Central
   - Creates GitHub Release tag `v1.0.1`
   - Bumps pom.xml to `1.0.2-SNAPSHOT` and pushes back to main

### Manual release
Trigger the workflow manually from the GitHub Actions UI:

```bash
gh workflow run deploy.yml \
  --repo Miguel-Sanchez241001/dep-inspector-release \
  --field sha=<commit-sha> \
  --field version=<version>
```

Or use the **workflow_dispatch** trigger (add `workflow_dispatch:` to `deploy.yml` `on:` block).

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| GPG signing fails | Ensure `gpg.passphrase` is set or the key has no passphrase |
| Sonatype 401 | Regenerate user token at central.sonatype.com |
| Push to plugin repo fails | Check `PLUGIN_REPO_PAT` scope (needs Contents: write on that repo) |
| `trigger-release` not firing | Ensure `RELEASE_REPO_PAT` has Contents: write on **this** repo |
