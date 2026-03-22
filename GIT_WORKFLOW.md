# Git Workflow

## Branch overview

| Branch | Purpose | Direct commits |
|---|---|---|
| `main` | Production-ready code. Every push triggers a release. | No — PRs only |
| `develop` | Integration branch. All features and fixes land here first. | No — PRs only |
| `feat/*` | A new feature or improvement. | Yes |
| `fix/*` | A bug fix for non-critical issues. | Yes |
| `hotfix/*` | A critical production fix that cannot wait for the next release cycle. | Yes |

---

## Standard flow — feature or fix

```
feat/my-feature  ──────────────────────────────────────────►  (deleted)
                  \                                        /
develop  ──────────┴────────────────────────────────────►──────────►
                                                          \         \
main     ──────────────────────────────────────────────────┴─────►───  → release v0.1.x
```

1. **Branch off `develop`**

   ```bash
   git checkout develop
   git pull
   git checkout -b feat/my-feature   # or fix/my-bug
   ```

2. **Work on the branch** — commit as often as you like.

3. **Open a PR into `develop`** — get it reviewed and merged.

4. **Repeat** until `develop` contains everything intended for the next release.

5. **Open a release PR from `develop` into `main`** — this is the larger PR that describes all changes included in the release. Once merged, the release pipeline creates a new `vMAJOR.MINOR.PATCH` tag and GitHub release automatically.

6. **After the release PR is merged**, keep `develop` up to date:

   ```bash
   git checkout develop
   git pull origin main
   git push
   ```

---

## Hotfix flow — critical production fix

A hotfix bypasses `develop` and goes directly to `main` to unblock production as fast as possible. It is then backported to `develop` so it is not lost in the next release cycle.

```
hotfix/critical-bug  ─────────────────►  (deleted)
                       \             /          \
main     ───────────────┴──────────►────────────  → release v0.1.x
                                                \
develop  ────────────────────────────────────────┴────────────────►
```

1. **Branch off `main`**

   ```bash
   git checkout main
   git pull
   git checkout -b hotfix/critical-bug
   ```

2. **Fix the bug** — keep the scope minimal. Only fix what is broken.

3. **Open a PR into `main`** — label it `hotfix` for visibility. Once merged, the release pipeline fires and publishes a new patch release immediately.

4. **Backport to `develop`** — either cherry-pick the commit(s) or open a second PR:

   ```bash
   # Option A — cherry-pick (preferred for small, self-contained fixes)
   git checkout develop
   git pull
   git cherry-pick <commit-sha>
   git push origin develop

   # Option B — open a backport PR
   git checkout -b hotfix/critical-bug-backport origin/develop
   git cherry-pick <commit-sha>
   git push origin hotfix/critical-bug-backport
   # → open PR into develop
   ```

   > Always backport. A hotfix that is never merged into `develop` will be silently reverted the next time `develop` is released to `main`.

---

## Branch naming

| Prefix | When to use | Example |
|---|---|---|
| `feat/` | New functionality or improvement | `feat/grafana-export` |
| `fix/` | Non-critical bug fix | `fix/pdf-score-delta` |
| `hotfix/` | Critical fix needed in production immediately | `hotfix/pushgateway-405` |
| `chore/` | Maintenance with no user-visible change | `chore/update-dependencies` |
| `docs/` | Documentation only | `docs/macos-install-guide` |

---

## Release cadence

There is no fixed release schedule. A release is created automatically the moment a PR is merged into `main` — whether that is a planned release PR from `develop` or an emergency hotfix.

To control what goes into a release, control what gets merged into `main`.
To bump the minor or major version, edit the `VERSION` file on `develop` and include it in the next release PR. See [GIT_WORKFLOW: Releases & versioning](README.md#releases--versioning) for details.

---

## Quick-reference

```
# Start a feature
git checkout develop && git pull
git checkout -b feat/<name>
# ... commit, push, open PR → develop

# Start a fix
git checkout develop && git pull
git checkout -b fix/<name>
# ... commit, push, open PR → develop

# Release (promote develop to main)
# Open PR: develop → main
# After merge the pipeline tags and publishes the release automatically.

# Hotfix
git checkout main && git pull
git checkout -b hotfix/<name>
# ... commit, push, open PR → main
# After merge: cherry-pick into develop (see above)
```
