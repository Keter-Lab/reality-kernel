# RK-α Client Portal (public repo)

Public-facing client dashboard + serverless API for the RK-α Reality Kernel.

**This repo is safe to push to a PUBLIC GitHub repo.** It contains:
- The client login + dashboard (HTML/CSS/JS)
- The serverless API that reads/writes Supabase
- The core reality engine.

It does **NOT** contain:
- Any secrets (Supabase keys live in Vercel env vars only)
- The admin tooling for creating/revoking keys (that lives in a separate
  PRIVATE repo on your local machine — see `rk-admin-private/`)

## Architecture

```
   Client browser  ──▶  Vercel static (this repo's /public)
                  ──▶  Vercel Python functions (this repo's /api)
                                │
                                ▼
                          Supabase (Postgres)
                                ▲
                                │
                Your laptop ──▶  admin CLI / local UI
                (rk-admin-private repo, never published)
```

Change keys on your laptop → Supabase updates → public site sees it instantly.
No 24/7 server. No secrets in this repo.

## Deploy

See `../DEPLOY_WALKTHROUGH.md` in the parent folder.

Quick version:
1. `vercel link` → pick a Vercel project.
2. In Vercel dashboard set env vars `SUPABASE_URL` and `SUPABASE_SERVICE_KEY`.
3. `git push` (Vercel auto-deploys).
4. Point your name.com domain at Vercel.

## Local dev

```bash
pip install -r requirements.txt
export SUPABASE_URL=https://xxxx.supabase.co
export SUPABASE_SERVICE_KEY=eyJ...
uvicorn api.index:app --reload --port 8000
# In another terminal:
cd public && python -m http.server 3000
# Open http://localhost:3000
```

The dashboard auto-detects `localhost` and points at `http://localhost:8000` for the API.
