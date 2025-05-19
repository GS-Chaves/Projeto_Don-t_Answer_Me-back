from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
import secrets
import datetime
import sqlite3
import os
import requests

app = FastAPI()
security = HTTPBasic()

# Allow frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database init
DB_PATH = "users.db"
MAX_REQUESTS_PER_MONTH = 100

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                password TEXT,
                request_count INTEGER,
                last_reset TEXT
            )
        ''')

# Auth check
def get_current_user(credentials: HTTPBasicCredentials = Depends(security)):
    email = credentials.username
    password = credentials.password
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT password, request_count, last_reset FROM users WHERE email = ?", (email,)).fetchone()
        if not row or not secrets.compare_digest(password, row[0]):
            raise HTTPException(status_code=401, detail="Credenciais inválidas")

        request_count, last_reset = row[1], row[2]
        today = datetime.date.today()

        # Reset monthly count
        if last_reset != str(today.replace(day=1)):
            conn.execute("UPDATE users SET request_count = 0, last_reset = ? WHERE email = ?", (str(today.replace(day=1)), email))
            request_count = 0

        if request_count >= MAX_REQUESTS_PER_MONTH:
            raise HTTPException(status_code=429, detail="Limite de requisições atingido para este mês")

        conn.execute("UPDATE users SET request_count = request_count + 1 WHERE email = ?", (email,))
        return email

# Model
class Prompt(BaseModel):
    message: str

@app.post("/generate")
def generate_response(prompt: Prompt, user: str = Depends(get_current_user)):
    instruction = (
        "Você é um professor paciente e didático. "
        "Explique de forma clara e passo a passo, como se estivesse ajudando um aluno a entender o conteúdo. "
        "Sempre incentive o raciocínio do aluno e evite dar a resposta diretamente logo de cara.\n\n"
    )

    full_prompt = instruction + prompt.message

    response = requests.post("http://localhost:11434/api/generate", json={
        "model": "llama3.1",
        "prompt": full_prompt,
        "stream": False
    })

    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Erro ao se comunicar com o Ollama")

    data = response.json()
    return {"response": data.get("response", "")}


# Usuários cadastrados manualmente
def seed_users():
    users = [
        ("aluno1@escola.edu", "w.12345678901"),
        ("aluno2@escola.edu", "w.10987654321")
    ]
    today = str(datetime.date.today().replace(day=1))
    with sqlite3.connect(DB_PATH) as conn:
        for email, password in users:
            conn.execute("INSERT OR IGNORE INTO users (email, password, request_count, last_reset) VALUES (?, ?, 0, ?)",
                         (email, password, today))

# Inicializa banco
if not os.path.exists(DB_PATH):
    init_db()
    seed_users()
