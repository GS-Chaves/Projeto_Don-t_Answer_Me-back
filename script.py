from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import psycopg2
import secrets
import datetime
import os
import requests
from jose import JWTError, jwt

app = FastAPI()
token_auth_scheme = HTTPBearer()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Config
DB_CONFIG = {
    "dbname": "fastapi_db",
    "user": "fastapi_user",
    "password": "fastapi_pass",
    "host": "localhost",
    "port": 5434
}
MAX_REQUESTS_PER_MONTH = 100
JWT_SECRET = "super-secret-key"
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 60

# Banco
def get_db_conn():
    return psycopg2.connect(**DB_CONFIG)

def init_db():
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    email TEXT PRIMARY KEY,
                    password TEXT NOT NULL,
                    request_count INTEGER NOT NULL,
                    last_reset DATE NOT NULL
                )
            ''')
        conn.commit()

# JWT helpers
def create_token(email: str):
    expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=JWT_EXPIRATION_MINUTES)
    payload = {"sub": email, "exp": expiration}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload["sub"]
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido ou expirado")

# Models
class Prompt(BaseModel):
    message: str

class LoginData(BaseModel):
    email: str
    password: str

token_auth_scheme = HTTPBearer()

# Auth com JWT
@app.post("/login")
def login(data: LoginData):
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT password FROM users WHERE email = %s", (data.email,))
            row = cur.fetchone()
            if not row or not secrets.compare_digest(data.password, row[0]):
                raise HTTPException(status_code=401, detail="Credenciais inválidas")
    token = create_token(data.email)
    return {"access_token": token}

# Dependência de segurança
def get_current_user(token: HTTPAuthorizationCredentials = Depends(token_auth_scheme)):
    email = verify_token(token.credentials)
    today = datetime.date.today()
    first_day = today.replace(day=1)

    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT request_count, last_reset FROM users WHERE email = %s", (email,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=401, detail="Usuário não encontrado")

            request_count, last_reset = row

            if last_reset != first_day:
                cur.execute("UPDATE users SET request_count = 0, last_reset = %s WHERE email = %s", (first_day, email))
                request_count = 0

            if request_count >= MAX_REQUESTS_PER_MONTH:
                raise HTTPException(status_code=429, detail="Limite de requisições atingido para este mês")

            cur.execute("UPDATE users SET request_count = request_count + 1 WHERE email = %s", (email,))
        conn.commit()
    return email

# Geração
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

# Seed
def seed_users():
    users = [
        ("aluno1@escola.edu", "w.12345678901"),
        ("aluno2@escola.edu", "w.10987654321")
    ]
    today = datetime.date.today().replace(day=1)

    with get_db_conn() as conn:
        with conn.cursor() as cur:
            for email, password in users:
                cur.execute("""
                    INSERT INTO users (email, password, request_count, last_reset)
                    VALUES (%s, %s, 0, %s)
                    ON CONFLICT (email) DO NOTHING
                """, (email, password, today))
        conn.commit()

# Init
try:
    init_db()
    seed_users()
except Exception as e:
    print("Erro ao inicializar o banco:", e)
