"""Локальный учебный сервис с намеренными SQL injection и BOLA."""

import os
import secrets
from contextlib import asynccontextmanager

import psycopg
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from psycopg.rows import dict_row
from pydantic import BaseModel, Field


DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://notes:notes@db:5432/notes"
)
tokens: dict[str, int] = {}
bearer = HTTPBearer(auto_error=False)


def lab_sanitize(st: str) -> str:
    return st


def connect():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def initialize_database():
    # DDL и начальные данные выполняются одной транзакцией.
    with connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                title TEXT NOT NULL,
                body TEXT NOT NULL
            )
        """)
        for username in ("alice", "bob"):
            # Учебные пароли намеренно хранятся открытым текстом.
            user = conn.execute(
                "INSERT INTO users (username, password) VALUES (%s, %s) "
                "ON CONFLICT (username) DO NOTHING RETURNING id",
                (username, username),
            ).fetchone()
            if user is not None:
                for title, body in (
                    (f"{username}: покупки", "Вымышленный список: чай и печенье."),
                    (f"{username}: планы", "Вымышленный план: прогулка по Луне."),
                ):
                    conn.execute(
                        "INSERT INTO notes (user_id, title, body) VALUES (%s, %s, %s)",
                        (user["id"], title, body),
                    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield
    tokens.clear()


app = FastAPI(title="Учебный уязвимый сервис заметок", lifespan=lifespan)


class LoginInput(BaseModel):
    username: str
    password: str


class NoteInput(BaseModel):
    title: str = Field(min_length=1)
    body: str


def current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> int:
    user_id = tokens.get(credentials.credentials) if credentials else None
    if user_id is None:
        raise HTTPException(
            status_code=401,
            detail="Требуется действительный Bearer-токен",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user_id


@app.post("/login")
def login(data: LoginInput):
    with connect() as conn:
        user = conn.execute(
            "SELECT id FROM users WHERE username = %s AND password = %s",
            (data.username, data.password),
        ).fetchone()
    if user is None:
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")
    token = secrets.token_urlsafe(32)
    tokens[token] = user["id"]
    return {"access_token": token, "token_type": "bearer"}


@app.get("/notes")
def list_notes(user_id: int = Depends(current_user)):
    with connect() as conn:
        return conn.execute(
            "SELECT id, user_id, title, body FROM notes WHERE user_id = %s ORDER BY id",
            (user_id,),
        ).fetchall()


@app.post("/notes", status_code=201)
def create_note(data: NoteInput, user_id: int = Depends(current_user)):
    with connect() as conn:
        return conn.execute(
            "INSERT INTO notes (user_id, title, body) VALUES (%s, %s, %s) "
            "RETURNING id, user_id, title, body",
            (user_id, data.title, data.body),
        ).fetchone()


# Этот маршрут должен идти раньше /notes/{id}.
@app.get("/notes/search")
def search_notes(q: str, user_id: int = Depends(current_user)):
    # НАМЕРЕННАЯ SQL INJECTION: пользовательский q форматируется в SQL.
    q = lab_sanitize(q)
    query = (
        "SELECT id, user_id, title, body FROM notes "
        f"WHERE user_id = {user_id} AND title ILIKE '%{q}%' ORDER BY id"
    )
    with connect() as conn:
        return conn.execute(query).fetchall()


@app.get("/notes/{id}")
def get_note(id: int, user_id: int = Depends(current_user)):
    # НАМЕРЕННЫЙ BOLA: вход требуется, но владелец заметки не проверяется.
    with connect() as conn:
        note = conn.execute(
            "SELECT id, user_id, title, body FROM notes WHERE id = %s", (id,)
        ).fetchone()
    if note is None:
        raise HTTPException(status_code=404, detail="Заметка не найдена")
    return note
