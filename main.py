
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from jose import JWTError, jwt
from cryptography.fernet import Fernet
import uuid, os

app = FastAPI()

# Mock database and secret keys
users_db = {}
files_db = []
JWT_SECRET = "jwtsecret"
FERNET_KEY = Fernet.generate_key()
fernet = Fernet(FERNET_KEY)

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

class LoginSchema(BaseModel):
    username: str
    password: str

class UserSignupSchema(BaseModel):
    username: str
    email: EmailStr
    password: str

class User:
    def __init__(self, username, email, password, role, verified=False):
        self.id = str(uuid.uuid4())
        self.username = username
        self.email = email
        self.password = password
        self.role = role
        self.verified = verified

def create_jwt_token(user):
    return jwt.encode({"sub": user.id, "role": user.role}, JWT_SECRET, algorithm="HS256")

def get_current_user(token: str = Depends(lambda: "")):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        uid = payload.get("sub")
        role = payload.get("role")
        user = next((u for u in users_db.values() if u.id == uid), None)
        if not user:
            raise HTTPException(403)
        return user
    except JWTError:
        raise HTTPException(403)

@app.post("/ops/login")
def ops_login(credentials: LoginSchema):
    user = users_db.get(credentials.username)
    if user and user.password == credentials.password and user.role == "ops":
        return {"token": create_jwt_token(user)}
    raise HTTPException(403, "Unauthorized")

@app.post("/ops/upload")
def upload_file(file: UploadFile = File(...), user=Depends(get_current_user)):
    if user.role != "ops":
        raise HTTPException(403, "Only ops can upload")
    ext = file.filename.split('.')[-1]
    if ext not in ["pptx", "docx", "xlsx"]:
        raise HTTPException(400, "Invalid file type")
    file_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, file_id + "." + ext)
    with open(file_path, "wb") as f:
        f.write(file.file.read())
    files_db.append({"id": file_id, "name": file.filename, "path": file_path})
    return {"message": "Upload successful"}

@app.post("/client/signup")
def client_signup(user_data: UserSignupSchema):
    if user_data.username in users_db:
        raise HTTPException(400, "Username exists")
    user = User(user_data.username, user_data.email, user_data.password, "client")
    users_db[user_data.username] = user
    token = fernet.encrypt(user.email.encode()).decode()
    url = f"http://localhost:8000/client/verify-email/{token}"
    return {"message": "Signup successful", "verification-url": url}

@app.get("/client/verify-email/{token}")
def verify_email(token: str):
    try:
        email = fernet.decrypt(token.encode()).decode()
        user = next((u for u in users_db.values() if u.email == email), None)
        if user:
            user.verified = True
            return {"message": "Email verified"}
    except Exception:
        pass
    raise HTTPException(400, "Invalid/Expired Token")

@app.post("/client/login")
def client_login(credentials: LoginSchema):
    user = users_db.get(credentials.username)
    if user and user.password == credentials.password and user.role == "client":
        return {"token": create_jwt_token(user)}
    raise HTTPException(403, "Unauthorized")

@app.get("/client/files")
def list_files(user=Depends(get_current_user)):
    if user.role != "client":
        raise HTTPException(403)
    return {"files": [f["name"] for f in files_db]}

@app.get("/client/download-file/{file_id}")
def get_download_link(file_id: str, user=Depends(get_current_user)):
    if user.role != "client":
        raise HTTPException(403)
    token = fernet.encrypt(f"{file_id}|{user.id}".encode()).decode()
    return {"download-link": f"http://localhost:8000/download/{token}", "message": "success"}

@app.get("/download/{token}")
def secure_download(token: str, user=Depends(get_current_user)):
    try:
        data = fernet.decrypt(token.encode()).decode()
        file_id, uid = data.split("|")
        if uid != user.id:
            raise HTTPException(403)
        file = next((f for f in files_db if f["id"] == file_id), None)
        if not file:
            raise HTTPException(404)
        return FileResponse(path=file["path"], filename=file["name"])
    except Exception:
        raise HTTPException(403)
