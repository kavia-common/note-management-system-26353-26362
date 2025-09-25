import os
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    func,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, relationship, sessionmaker

# -----------------------------------------------------------------------------
# Environment/config
# -----------------------------------------------------------------------------
# Note: Do not hardcode secrets. These must be provided via environment variables.
# Required env vars (example names):
#   POSTGRES_URL, POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB, POSTGRES_PORT
#   AUTH_SECRET (shared secret for demo token auth) - orchestrator should set it.
#   ALLOW_ORIGINS (optional CSV for CORS)
#
# We will construct the SQLAlchemy URL from individual env variables if POSTGRES_URL is not present.

def _build_db_url_from_env() -> Optional[str]:
    host = os.getenv("POSTGRES_URL")
    if host:
        # If full SQLAlchemy URL provided, use it as-is
        if host.startswith("postgresql://") or host.startswith("postgresql+psycopg://"):
            return host
        # Otherwise treat POSTGRES_URL as host/address and build full URL
    user = os.getenv("POSTGRES_USER")
    password = os.getenv("POSTGRES_PASSWORD")
    db = os.getenv("POSTGRES_DB")
    port = os.getenv("POSTGRES_PORT", "5432")
    host_only = os.getenv("POSTGRES_URL") or "localhost"
    if user and password and db:
        return f"postgresql+psycopg://{user}:{password}@{host_only}:{port}/{db}"
    return None

DATABASE_URL = _build_db_url_from_env() or "sqlite:///./local_fallback.db"

# Create SQLAlchemy engine
# - For PostgreSQL we expect 'postgresql+psycopg://'
# - For local fallback we use SQLite to keep app running without DB setup
engine = create_engine(
    DATABASE_URL,
    echo=False,
    future=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


# -----------------------------------------------------------------------------
# Database Models
# -----------------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(254), unique=True, index=True, nullable=False)
    # In a real application, store password hashes and use proper auth flows.
    # For this demo, we use token-only auth, but keep the column for future use.
    password_hash = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    notes = relationship("Note", back_populates="owner", cascade="all, delete-orphan")


class Note(Base):
    __tablename__ = "notes"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    content = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    owner = relationship("User", back_populates="notes")


# Create tables if they don't exist (idempotent).
# In production, use migrations. This is for initial bootstrapping.
Base.metadata.create_all(bind=engine)


# -----------------------------------------------------------------------------
# Pydantic Schemas
# -----------------------------------------------------------------------------
class UserOut(BaseModel):
    id: int = Field(..., description="User ID")
    email: str = Field(..., description="User email")

    class Config:
        from_attributes = True


class NoteBase(BaseModel):
    title: str = Field(..., description="Title of the note", min_length=1, max_length=255)
    content: Optional[str] = Field(None, description="Content of the note (optional)")


class NoteCreate(NoteBase):
    pass


class NoteUpdate(BaseModel):
    title: Optional[str] = Field(None, description="Updated title", min_length=1, max_length=255)
    content: Optional[str] = Field(None, description="Updated content")


class NoteOut(NoteBase):
    id: int = Field(..., description="Note ID")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")

    class Config:
        from_attributes = True


# -----------------------------------------------------------------------------
# Auth (Demo token-based)
# -----------------------------------------------------------------------------
bearer_scheme = HTTPBearer(auto_error=True)

def get_db():
    """FastAPI dependency to provide a DB session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# PUBLIC_INTERFACE
def verify_token_and_get_user(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """
    This is a public function for token verification. It expects a Bearer token.
    For demo purposes:
      - Token format: "token:<email>"
      - If user with that email doesn't exist, it will be auto-created.

    In production, replace with JWT validation or a proper auth provider.
    """
    token = credentials.credentials
    # Very basic demo secret gate (optional)
    expected_prefix = "token:"
    if not token.startswith(expected_prefix):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format")
    email = token[len(expected_prefix) :].strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token email")

    # Fetch or create user
    user = db.query(User).filter(User.email == email).first()
    if not user:
        user = User(email=email)
        db.add(user)
        db.commit()
        db.refresh(user)
    return user


# -----------------------------------------------------------------------------
# FastAPI App
# -----------------------------------------------------------------------------
app = FastAPI(
    title="Notes Backend API",
    description="FastAPI backend for a Notes application with token-based auth. Use Authorization: Bearer token:<email>.",
    version="0.1.0",
    openapi_tags=[
        {"name": "Health", "description": "Health check endpoints"},
        {"name": "Notes", "description": "CRUD operations for notes"},
        {"name": "Realtime", "description": "WebSocket usage information"},
    ],
)

allowed_origins_env = os.getenv("ALLOW_ORIGINS", "*")
allow_origins = [o.strip() for o in allowed_origins_env.split(",")] if allowed_origins_env else ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.get("/", tags=["Health"], summary="Health Check")
def health_check():
    """Simple health check endpoint."""
    return {"message": "Healthy"}

# PUBLIC_INTERFACE
@app.get(
    "/notes",
    response_model=List[NoteOut],
    tags=["Notes"],
    summary="List notes for current user",
    description="Returns all notes belonging to the authenticated user.",
    responses={
        200: {"description": "List of notes"},
        401: {"description": "Unauthorized"},
    },
)
def list_notes(current_user: User = Depends(verify_token_and_get_user), db: Session = Depends(get_db)):
    """
    Retrieve all notes for the authenticated user.
    """
    items = db.query(Note).filter(Note.user_id == current_user.id).order_by(Note.created_at.desc()).all()
    return items

# PUBLIC_INTERFACE
@app.post(
    "/notes",
    response_model=NoteOut,
    status_code=status.HTTP_201_CREATED,
    tags=["Notes"],
    summary="Create a new note",
    description="Creates a new note for the authenticated user.",
    responses={
        201: {"description": "Note created"},
        400: {"description": "Bad request"},
        401: {"description": "Unauthorized"},
    },
)
def create_note(payload: NoteCreate, current_user: User = Depends(verify_token_and_get_user), db: Session = Depends(get_db)):
    """
    Create a new note owned by the authenticated user.
    """
    note = Note(
        user_id=current_user.id,
        title=payload.title,
        content=payload.content or "",
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    return note

# PUBLIC_INTERFACE
@app.put(
    "/notes/{note_id}",
    response_model=NoteOut,
    tags=["Notes"],
    summary="Update a note",
    description="Updates the note with provided fields. Only the owner can update it.",
    responses={
        200: {"description": "Note updated"},
        400: {"description": "Bad request"},
        401: {"description": "Unauthorized"},
        404: {"description": "Note not found"},
    },
)
def update_note(
    note_id: int,
    payload: NoteUpdate,
    current_user: User = Depends(verify_token_and_get_user),
    db: Session = Depends(get_db),
):
    """
    Update the specified note. Only the owner can update it.
    """
    note: Optional[Note] = db.query(Note).filter(Note.id == note_id, Note.user_id == current_user.id).first()
    if not note:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")

    changed = False
    if payload.title is not None:
        note.title = payload.title
        changed = True
    if payload.content is not None:
        note.content = payload.content
        changed = True

    if changed:
        # Explicitly set updated_at for SQLite fallback; PostgreSQL trigger via onupdate should handle it too.
        note.updated_at = datetime.now(timezone.utc)
        db.add(note)
        db.commit()
        db.refresh(note)

    return note

# PUBLIC_INTERFACE
@app.delete(
    "/notes/{note_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Notes"],
    summary="Delete a note",
    description="Deletes the note. Only the owner can delete it.",
    responses={
        204: {"description": "Note deleted"},
        401: {"description": "Unauthorized"},
        404: {"description": "Note not found"},
    },
)
def delete_note(note_id: int, current_user: User = Depends(verify_token_and_get_user), db: Session = Depends(get_db)):
    """
    Delete the specified note if owned by the authenticated user.
    """
    note: Optional[Note] = db.query(Note).filter(Note.id == note_id, Note.user_id == current_user.id).first()
    if not note:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    db.delete(note)
    db.commit()
    # 204 No Content
    return None


# -----------------------------------------------------------------------------
# WebSocket docs helper (project-level usage note)
# -----------------------------------------------------------------------------
# PUBLIC_INTERFACE
@app.get(
    "/realtime-info",
    tags=["Realtime"],
    summary="WebSocket usage",
    description="Notes app does not currently expose realtime WebSocket endpoints. This route explains how a future WS would be documented.",
    responses={200: {"description": "Usage info"}},
)
def websocket_usage_info():
    """
    This project currently has no WebSocket endpoints.
    If/when added, the endpoint(s) would be documented with explicit operation_id,
    tags, and usage notes. For example:
      - ws://<host>/ws/notes
      - Clients connect and authenticate with a token, then receive updates.
    """
    return {
        "message": "No WebSocket endpoints yet. This route documents how realtime endpoints would be described in OpenAPI."
    }
