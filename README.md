# note-management-system-26353-26362

## Notes Backend (FastAPI)
- Location: notes_backend
- Run (example):
  - pip install -r notes_backend/requirements.txt
  - python notes_backend/run.py  # binds to 0.0.0.0:3001 by default (set PORT to override)
  - # Alternative:
  - # PORT=3001 uvicorn src.api.main:app --host 0.0.0.0 --port ${PORT}
- OpenAPI docs at /docs

### Auth (Demo)
Use an Authorization header:
  Authorization: Bearer token:<email>
The backend will auto-create a user for that email if one does not exist.

Login endpoint (for frontend compatibility):
- POST /auth/login
  - Request body: { "email": "<you@example.com>", "password": "<ignored>" }
  - Response: { "access_token": "token:<email>", "token_type": "bearer", "user": { ... } }

### Endpoints
- POST /auth/login - demo login returning a bearer token
- GET /notes - list current user's notes
- POST /notes - create a new note
- PUT /notes/{id} - update a note
- DELETE /notes/{id} - delete a note

### Frontend configuration
The frontend expects REACT_APP_API_BASE_URL to point to this backend.
Set it to the backend base URL (no trailing slash), e.g.:
- REACT_APP_API_BASE_URL=http://localhost:3001
or for the running environment:
- REACT_APP_API_BASE_URL=https://vscode-internal-13658-qa.qa01.cloud.kavia.ai:3001

### Environment
See notes_backend/.env.example for required variables.
The app will fall back to a local SQLite file (local_fallback.db) if PostgreSQL env is not set, but production should use PostgreSQL.

Database driver and URL notes:
- The backend supports PostgreSQL via SQLAlchemy. The project includes psycopg v3 (psycopg[binary]) and also has psycopg2-binary available in the environment to cover legacy URLs.
- Recommended: use a SQLAlchemy URL with the psycopg v3 driver, for example:
  postgresql+psycopg://USER:PASSWORD@HOST:PORT/DBNAME
- If you set POSTGRES_URL to a URL beginning with postgresql:// (defaulting to psycopg2), it will work because psycopg2-binary is present, but prefer postgresql+psycopg for consistency with the pinned dependency in requirements.txt.