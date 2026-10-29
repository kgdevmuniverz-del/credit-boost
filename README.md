# Credit Boost
Private, single-user credit repair tracker (Node/Express + Postgres). Neon UI.

Env vars (set in Render, never committed): `ADMIN_USERNAME` (default `kai`), `ADMIN_PASSWORD`, `SESSION_SECRET`, `DATABASE_URL` (Render Postgres *Internal Database URL*). Without `DATABASE_URL` the app runs on a temporary in-memory DB.

No SSNs are collected or stored; account numbers are truncated to last 4. No analytics or third-party scripts.

## Keep-alive (free plan)
Render free web services sleep after ~15 min idle (cold start ≈ 30–60 s). `.github/workflows/keepalive.yml` pings `/healthz` every 10 min. `/healthz` is served before the session layer (no DB, no session row). GitHub scheduled runs are best-effort and can be delayed; GitHub disables scheduled workflows after 60 days with no repo activity — re-enable under Actions if pings stop. Running 24/7 uses ~730 of the 750 free instance-hours per workspace each month.
