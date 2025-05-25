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
from passlib.context import CryptContext

app = FastAPI()
token_auth_scheme = HTTPBearer()

# Configuração para o hashing de senhas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

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
                    full_name TEXT,
                    institution TEXT,
                    request_count INTEGER NOT NULL,
                    last_reset DATE NOT NULL
                )
            ''')
            conn.commit()

            # --- Adição de colunas existentes com tratamento de erro (para desenvolvimento) ---
            # Este bloco pode ser removido após a primeira execução bem-sucedida
            # e a confirmação de que as colunas existem no seu DB.
            try:
                cur.execute("ALTER TABLE users ADD COLUMN full_name TEXT")
                conn.commit()
                print("Coluna 'full_name' adicionada.")
            except psycopg2.errors.DuplicateColumn:
                conn.rollback()
                print("Coluna 'full_name' já existe.")
            except Exception as e:
                conn.rollback()
                print(f"Erro ao adicionar 'full_name': {e}")

            try:
                cur.execute("ALTER TABLE users ADD COLUMN institution TEXT")
                conn.commit()
                print("Coluna 'institution' adicionada.")
            except psycopg2.errors.DuplicateColumn:
                conn.rollback()
                print("Coluna 'institution' já existe.")
            except Exception as e:
                conn.rollback()
                print(f"Erro ao adicionar 'institution': {e}")
            # --- Fim da adição de colunas existentes ---


# Funções auxiliares para hashing de senha
def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)


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

# --- A FUNÇÃO 'get_current_user' FOI MOVIDA PARA AQUI! ---
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

            cur.execute("UPDATE users SET request_count = request_count + 1 WHERE email = %s", (email,))
            conn.commit()
    return email
# --- FIM DA MOVIÇÃO ---


# Models
class Prompt(BaseModel):
    message: str

class LoginData(BaseModel):
    email: str
    password: str

class RegisterData(BaseModel):
    full_name: str
    institution: str
    email: str
    password: str

# Novo modelo para retornar dados do usuário (sem a senha)
class UserOut(BaseModel):
    email: str
    password: str
    full_name: str | None = None
    institution: str | None = None
    request_count: int
    last_reset: datetime.date


# Auth com JWT
@app.post("/login")
def login(data: LoginData):
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT password FROM users WHERE email = %s", (data.email,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=401, detail="Credenciais inválidas")

            stored_hashed_password = row[0]
            if not verify_password(data.password, stored_hashed_password):
                raise HTTPException(status_code=401, detail="Credenciais inválidas")
    token = create_token(data.email)
    return {"access_token": token}

@app.post("/register")
def register_user(data: RegisterData):
    today = datetime.date.today().replace(day=1)
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT email FROM users WHERE email = %s", (data.email,))
            if cur.fetchone():
                raise HTTPException(status_code=400, detail="Este email já está cadastrado.")

            hashed_password = hash_password(data.password)

            cur.execute(
                """
                INSERT INTO users (email, password, full_name, institution, request_count, last_reset)
                VALUES (%s, %s, %s, %s, 0, %s)
                """,
                (data.email, hashed_password, data.full_name, data.institution, today)
            )
            conn.commit()
    return {"message": "Usuário cadastrado com sucesso!"}

# Endpoint para listar todos os usuários
@app.get("/users", response_model=list[UserOut])
def get_all_users(user: str = Depends(get_current_user)):
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            # Seleciona todos os campos, exceto a senha, para segurança
            cur.execute("SELECT email, password, full_name, institution, request_count, last_reset FROM users")
            users_data = cur.fetchall()

    users_list = []
    for row in users_data:
        users_list.append(UserOut(
            email=row[0],
            password=row[1],
            full_name=row[2],
            institution=row[3],
            request_count=row[4],
            last_reset=row[5]
        ))
    return users_list


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
        ("aluno1@escola.edu", "w.12345678901", "Aluno Um", "Escola Modelo A"),
        ("aluno2@escola.edu", "w.10987654321", "Aluno Dois", "Escola Modelo B")
    ]
    today = datetime.date.today().replace(day=1)

    with get_db_conn() as conn:
        with conn.cursor() as cur:
            for email, password, full_name, institution in users:
                hashed_password = hash_password(password)
                cur.execute("""
                    INSERT INTO users (email, password, full_name, institution, request_count, last_reset)
                    VALUES (%s, %s, %s, %s, 0, %s)
                    ON CONFLICT (email) DO NOTHING
                """, (email, hashed_password, full_name, institution, today))
        conn.commit()

# Init
try:
    init_db()
    seed_users()
except Exception as e:
    print("Erro ao inicializar o banco:", e)