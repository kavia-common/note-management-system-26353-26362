# Notes Backend Database Configuration

This backend connects to PostgreSQL using SQLAlchemy and psycopg v3.

Defaults for multi-container environment:
- Host: notes_database
- Port: 5000
- User: appuser
- Password: dbuser123
- Database: myapp
- Driver: postgresql+psycopg

Environment variables:
- POSTGRES_URL: Full SQLAlchemy URL (e.g., postgresql+psycopg://appuser:dbuser123@notes_database:5000/myapp)
- POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB, POSTGRES_PORT, POSTGRES_HOST: Individual components used to build the URL if POSTGRES_URL is not a full URL.

Important:
- Do not use localhost as the host in multi-container environments—use the service name (notes_database).
- The backend uses UUID primary keys for users and notes. For PostgreSQL, server_default is gen_random_uuid(); ensure the pgcrypto extension is enabled:
  CREATE EXTENSION IF NOT EXISTS pgcrypto;

SQLite fallback:
- If PostgreSQL is not reachable, the app falls back to local_fallback.db and generates UUIDs client-side to maintain compatibility.
