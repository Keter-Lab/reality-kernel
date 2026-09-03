# REPO_MIGRATION.md

## Zero-Downtime Migration: Personal GitHub Repo → Keter Labs Org Repo + Vercel

This guide migrates the Reality Kernel repo from a personal GitHub namespace to the Keter Labs organization while keeping production live.

---

## Goal

- Move source of truth from `github.com/<personal>/<repo>` to `github.com/keter-labs/<repo>`
- Reconnect Vercel to the org repo
- Preserve environment variables, domains, and API behavior
- Avoid production downtime

---

## Phase 0 — Preconditions (No Changes Yet)

1. Confirm org permissions in GitHub:
   - You can create repos in `keter-labs`
   - You can manage branch protection rules
2. Confirm Vercel permissions:
   - You can create/connect projects
   - You can manage domains and env vars
3. Freeze risky changes:
   - Announce a short migration window
   - Avoid schema-breaking backend edits during migration

---

## Phase 1 — Create Org Repository

1. In GitHub org `keter-labs`, create empty repo (same name preferred).
2. Do **not** initialize with README/license/gitignore.
3. Add branch protection on `main` (optional now, required before cutover).

---

## Phase 2 — Mirror Code to Org Repo (Safe, No Traffic Impact)

From a local clone of the current repo:

```bash
git remote -v
# origin -> personal repo

git remote add org git@github.com:keter-labs/<repo>.git
git fetch --all --tags

git push org --all
git push org --tags
```

Verify in GitHub UI:
- Branches present
- Tags present
- Commit history identical

---

## Phase 3 — Prepare New Vercel Project (Parallel Deployment)

> Keep the existing production Vercel project untouched during this phase.

1. In Vercel, create a **new project** from `keter-labs/<repo>`.
2. Configure **identical** settings:
   - Framework/build settings
   - Root directory (if not repository root)
   - Install/build commands
3. Copy all environment variables from old project to new project:
   - Production, Preview, Development scopes
   - Confirm values for `SUPABASE_URL`, `SUPABASE_SERVICE_KEY`, `RK_SECRET_KEY`, and allowed origins.
4. Deploy and test the new project on its Vercel preview/production URL (not customer domain yet).

---

## Phase 4 — Validate Before Cutover

Run the same checks against old and new deployments:

1. Health/API checks:
   - `GET /healthz`
   - `GET /v1/version`
   - authenticated smoke test on `/v1/check`
2. Frontend route checks:
   - `/`, `/pricing`, `/sdk`, `/integration`, `/playground`, `/security`, `/verifier`, `/dashboard`
3. Security checks:
   - CORS origin behavior
   - auth required endpoints reject missing/invalid keys
4. Audit checks:
   - decision writes audit rows
   - Ed25519 fields present for each audit insert

Proceed only when parity is confirmed.

---

## Phase 5 — Zero-Downtime Domain Cutover

### Option A (Recommended): Move custom domain to new project

1. Keep old project running.
2. Add production domain(s) to new project.
3. Update DNS records as instructed by Vercel.
4. Wait for SSL provisioning and domain verification.
5. Switch primary domain to new project only after health checks pass.

Because both projects remain live during DNS/edge propagation, users should not see downtime.

### Option B: Vercel project transfer (if available to your plan/process)

If your org policy allows project transfer and it preserves domain/env state, you may transfer project ownership instead of creating a second project. Still run pre/post transfer smoke tests.

---

## Phase 6 — Post-Cutover Monitoring (First 24h)

1. Monitor:
   - 4xx/5xx rates
   - latency p95/p99
   - Supabase error logs
2. Validate business flows:
   - login/dashboard access
   - API check throughput
   - audit insertion and retrieval
3. Keep old Vercel project as hot rollback target for at least 24 hours.

---

## Rollback Plan (Immediate)

If issues appear after cutover:

1. Re-point domain back to old Vercel project (or restore previous DNS target).
2. Confirm old `/healthz` and `/v1/check` pass.
3. Keep org project live for debugging on non-production URL.
4. Fix and reattempt cutover only after full regression pass.

---

## Finalization Checklist

- [ ] Org repo contains full history/tags
- [ ] Branch protection and required checks configured
- [ ] New Vercel project uses org repo
- [ ] All env vars replicated and verified
- [ ] Route/API/security smoke tests passed
- [ ] Domain cutover complete with no downtime observed
- [ ] Old project retained for rollback window, then decommissioned

---

## Notes Specific to This Workspace

- Keep `vercel.json` rewrites intact for API/public routing.
- Ensure `RK_ALLOWED_ORIGINS` includes final production origin(s) after cutover.
- Treat Ed25519 audit signing as mandatory; do not allow unsigned audit inserts.
