"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

import datetime
import hashlib
import hmac
import json
import os
import secrets
import threading
from pathlib import Path
from typing import Dict, Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

SECRET_KEY = os.environ.get("AUTH_SECRET_KEY", "dev-secret-change-me")
TOKEN_EXPIRATION_MINUTES = 60
DATA_DIR = current_dir / "data"
USERS_FILE = DATA_DIR / "users.json"
_users_lock = threading.Lock()


class AuthRequest(BaseModel):
    email: EmailStr
    password: str


class AuthTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


def _hash_password(password: str, salt: Optional[str] = None) -> Dict[str, str]:
    salt_bytes = secrets.token_bytes(16) if salt is None else bytes.fromhex(salt)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, 100_000)
    return {"salt": salt_bytes.hex(), "hash": pwd_hash.hex()}


def _verify_password(password: str, salt: str, expected_hash: str) -> bool:
    candidate = _hash_password(password, salt)
    return hmac.compare_digest(candidate["hash"], expected_hash)


def _create_token(email: str) -> str:
    now = datetime.datetime.utcnow()
    payload = {
        "sub": email,
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(minutes=TOKEN_EXPIRATION_MINUTES)).timestamp()),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    # PyJWT returns str on new versions and bytes on old; normalize
    return token if isinstance(token, str) else token.decode("utf-8")


def _decode_token(token: str) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
        return email
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


def _ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def _load_users_from_disk() -> Dict[str, Dict[str, str]]:
    _ensure_data_dir()
    if not USERS_FILE.exists():
        return {}
    try:
        with USERS_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _save_users_to_disk(users: Dict[str, Dict[str, str]]) -> None:
    _ensure_data_dir()
    temp_path = USERS_FILE.with_suffix(".tmp")
    with temp_path.open("w", encoding="utf-8") as f:
        json.dump(users, f)
    temp_path.replace(USERS_FILE)


auth_scheme = HTTPBearer(auto_error=False)


def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(auth_scheme)) -> str:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing credentials")
    return _decode_token(credentials.credentials)


# In-memory user store backed by file persistence
users: Dict[str, Dict[str, str]] = _load_users_from_disk()

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


@app.post("/auth/register", response_model=AuthTokenResponse)
def register_user(auth_request: AuthRequest):
    email = auth_request.email.lower()
    if len(auth_request.password) < 8:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must be at least 8 characters")

    with _users_lock:
        if email in users:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")

        pwd = _hash_password(auth_request.password)
        users[email] = {"hash": pwd["hash"], "salt": pwd["salt"]}
        _save_users_to_disk(users)
    token = _create_token(email)
    return AuthTokenResponse(access_token=token)


@app.post("/auth/login", response_model=AuthTokenResponse)
def login(auth_request: AuthRequest):
    email = auth_request.email.lower()
    user = users.get(email)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not _verify_password(auth_request.password, user["salt"], user["hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token = _create_token(email)
    return AuthTokenResponse(access_token=token)


@app.get("/auth/me")
def read_current_user(current_user: str = Depends(get_current_user)):
    return {"email": current_user}


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    return activities


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(activity_name: str, current_user: str = Depends(get_current_user)):
    """Sign up the current authenticated user for an activity"""
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    activity = activities[activity_name]
    email = current_user

    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(activity_name: str, current_user: str = Depends(get_current_user)):
    """Unregister the current authenticated user from an activity"""
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    activity = activities[activity_name]
    email = current_user

    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}
