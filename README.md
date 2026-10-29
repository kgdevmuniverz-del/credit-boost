# Credit Boost
Private, single-user credit repair tracker (Node/Express + Postgres). Neon UI.

Env vars (set in Render, never committed): `ADMIN_USERNAME` (default `kai`), `ADMIN_PASSWORD`, `SESSION_SECRET`, `DATABASE_URL` (Render Postgres *Internal Database URL*). Without `DATABASE_URL` the app runs on a temporary in-memory DB.

No SSNs are collected or stored; account numbers are truncated to last 4. No analytics or third-party scripts.
