#!/usr/bin/env python3
"""
PUBLIC_INTERFACE
Run the FastAPI Notes Backend using uvicorn.

This script:
- Loads environment variables from a local .env file if present.
- Determines the port to bind from the PORT environment variable (defaults to 3001).
- Starts uvicorn on host 0.0.0.0 at the chosen port, serving src.api.main:app.

Environment variables:
- PORT: Port for the HTTP server (default: 3001)
- ALLOW_ORIGINS: Comma-separated list of allowed origins for CORS (default: "*")
- POSTGRES_URL, POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB, POSTGRES_PORT: Optional DB configuration.
  If not set, the app will use a local SQLite fallback (local_fallback.db).

Usage:
  python run.py
  PORT=8080 python run.py
"""
import os

try:
    from dotenv import load_dotenv  # type: ignore
except Exception:
    # dotenv is in requirements; if missing, continue without it.
    def load_dotenv(*args, **kwargs):
        return False

def main() -> int:
    # Load .env if available to ease local/dev runs
    load_dotenv()

    # Read port; default to 3001 as required by the deployment environment
    port_str = os.getenv("PORT", "3001")
    try:
        port = int(port_str)
    except ValueError:
        # Fallback to default
        port = 3001

    host = os.getenv("HOST", "0.0.0.0")

    # Delay import of uvicorn to keep script importable without side effects
    import uvicorn

    # Log startup info to stdout
    print(f"[run.py] Starting Notes Backend on {host}:{port} (app: src.api.main:app)")
    uvicorn.run("src.api.main:app", host=host, port=port, reload=False, workers=1)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
