from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Float,
    ForeignKey,
    Text,
    TIMESTAMP
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, Session
from sqlalchemy.sql import func
from passlib.context import CryptContext
from jose import jwt, JWTError
from pydantic import BaseModel, EmailStr
from dotenv import load_dotenv
import os
from datetime import datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware

# ======================================================
# LOAD ENV
# ======================================================

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

SECRET_KEY = "SUPER_SECRET_KEY"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 7 * 24 * 60

# ======================================================
# DATABASE
# ======================================================

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=300,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()

# ======================================================
# FASTAPI
# ======================================================

app = FastAPI(title="Smart Farming Backend")

# ======================================================
# PASSWORD HASHING
# ======================================================

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# ======================================================
# AUTH
# ======================================================

security = HTTPBearer()

# ======================================================
# DATABASE MODELS
# ======================================================

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    full_name = Column(String(100))

    email = Column(String(255), unique=True, nullable=False)

    password_hash = Column(Text, nullable=False)

    phone = Column(String(20))

    created_at = Column(
        TIMESTAMP,
        server_default=func.now()
    )

    zones = relationship(
        "Zone",
        back_populates="user",
        cascade="all, delete"
    )

    complaints = relationship(
        "Complaint",
        back_populates="user",
        cascade="all, delete"
    )


class Zone(Base):
    __tablename__ = "zones"

    id = Column(Integer, primary_key=True)

    user_id = Column(
        Integer,
        ForeignKey("users.id")
    )

    zone_number = Column(Integer)

    zone_name = Column(
        String(100),
        default="Zone"
    )

    user = relationship(
        "User",
        back_populates="zones"
    )


class SensorReading(Base):
    __tablename__ = "sensor_readings"

    id = Column(Integer, primary_key=True)

    zone_id = Column(
        Integer,
        ForeignKey("zones.id")
    )

    sensor_1 = Column(Float)

    sensor_2 = Column(Float)

    recorded_at = Column(
        TIMESTAMP,
        server_default=func.now()
    )


class Complaint(Base):
    __tablename__ = "complaints"

    id = Column(Integer, primary_key=True)

    user_id = Column(
        Integer,
        ForeignKey("users.id")
    )

    subject = Column(String(255))

    message = Column(Text)

    status = Column(
        String(50),
        default="open"
    )

    created_at = Column(
        TIMESTAMP,
        server_default=func.now()
    )

    user = relationship(
        "User",
        back_populates="complaints"
    )

# ======================================================
# CREATE TABLES
# ======================================================

Base.metadata.create_all(bind=engine)

# ======================================================
# Pydantic Schemas
# ======================================================

class RegisterSchema(BaseModel):
    full_name: str
    email: EmailStr
    password: str
    phone: str


class LoginSchema(BaseModel):
    email: EmailStr
    password: str


class ChangeNameSchema(BaseModel):
    new_name: str


class ChangePasswordSchema(BaseModel):
    old_password: str
    new_password: str


class SensorSchema(BaseModel):
    zone_id: int
    sensor_1: float
    sensor_2: float


class ComplaintSchema(BaseModel):
    subject: str
    message: str


class RenameZoneSchema(BaseModel):
    zone_name: str

# ======================================================
# DATABASE DEPENDENCY
# ======================================================

def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()

# ======================================================
# UTILS
# ======================================================

def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str):
    return pwd_context.verify(password, hashed)


def create_access_token(data: dict):
    to_encode = data.copy()

    expire = datetime.utcnow() + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    to_encode.update({"exp": expire})

    return jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):

    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        user_id = payload.get("user_id")

        if user_id is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid token"
            )

    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )

    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    return user

# ======================================================
# HOME
# ======================================================

@app.get("/")
def home():
    return {
        "message": "Smart Farming Backend Running"
    }

# ======================================================
# REGISTER
# ======================================================

@app.post("/auth/register")
def register(
    data: RegisterSchema,
    db: Session = Depends(get_db)
):

    existing_user = db.query(User).filter(
        User.email == data.email
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email already exists"
        )

    user = User(
        full_name=data.full_name,
        email=data.email,
        password_hash=hash_password(data.password),
        phone=data.phone
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    # CREATE 8 ZONES AUTOMATICALLY
    for i in range(1, 9):

        zone = Zone(
            user_id=user.id,
            zone_number=i,
            zone_name=f"Zone {i}"
        )

        db.add(zone)

    db.commit()

    return {
        "message": "User registered successfully"
    }

# ======================================================
# LOGIN
# ======================================================

@app.post("/auth/login")
def login(
    data: LoginSchema,
    db: Session = Depends(get_db)
):

    user = db.query(User).filter(
        User.email == data.email
    ).first()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    if not verify_password(
        data.password,
        user.password_hash
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    token = create_access_token({
        "user_id": user.id
    })

    return {
        "access_token": token,
        "token_type": "bearer"
    }

# ======================================================
# USER PROFILE
# ======================================================

@app.get("/users/me")
def get_profile(
    current_user: User = Depends(get_current_user)
):

    return {
        "id": current_user.id,
        "full_name": current_user.full_name,
        "email": current_user.email,
        "phone": current_user.phone,
        "created_at": current_user.created_at
    }

# ======================================================
# CHANGE NAME
# ======================================================

@app.put("/users/change-name")
def change_name(
    data: ChangeNameSchema,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    current_user.full_name = data.new_name

    db.commit()

    return {
        "message": "Name updated"
    }

# ======================================================
# CHANGE PASSWORD
# ======================================================

@app.put("/users/change-password")
def change_password(
    data: ChangePasswordSchema,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    if not verify_password(
        data.old_password,
        current_user.password_hash
    ):
        raise HTTPException(
            status_code=400,
            detail="Old password incorrect"
        )

    current_user.password_hash = hash_password(
        data.new_password
    )

    db.commit()

    return {
        "message": "Password updated"
    }

# ======================================================
# GET ALL ZONES
# ======================================================

@app.get("/zones")
def get_zones(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    zones = db.query(Zone).filter(
        Zone.user_id == current_user.id
    ).all()

    return zones

# ======================================================
# RENAME ZONE
# ======================================================

@app.put("/zones/{zone_id}")
def rename_zone(
    zone_id: int,
    data: RenameZoneSchema,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    zone = db.query(Zone).filter(
        Zone.id == zone_id,
        Zone.user_id == current_user.id
    ).first()

    if not zone:
        raise HTTPException(
            status_code=404,
            detail="Zone not found"
        )

    zone.zone_name = data.zone_name

    db.commit()

    return {
        "message": "Zone renamed"
    }

# ======================================================
# ADD SENSOR DATA
# ======================================================

@app.post("/sensors/add")
def add_sensor_data(
    data: SensorSchema,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    zone = db.query(Zone).filter(
        Zone.id == data.zone_id,
        Zone.user_id == current_user.id
    ).first()

    if not zone:
        raise HTTPException(
            status_code=404,
            detail="Zone not found"
        )

    sensor = SensorReading(
        zone_id=data.zone_id,
        sensor_1=data.sensor_1,
        sensor_2=data.sensor_2
    )

    db.add(sensor)
    db.commit()

    return {
        "message": "Sensor data added"
    }

# ======================================================
# GET LATEST SENSOR DATA
# ======================================================

@app.get("/sensors/latest/{zone_id}")
def latest_sensor_data(
    zone_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    zone = db.query(Zone).filter(
        Zone.id == zone_id,
        Zone.user_id == current_user.id
    ).first()

    if not zone:
        raise HTTPException(
            status_code=404,
            detail="Zone not found"
        )

    latest = db.query(SensorReading).filter(
        SensorReading.zone_id == zone_id
    ).order_by(
        SensorReading.recorded_at.desc()
    ).first()

    if not latest:
        return {
            "message": "No sensor data"
        }

    return latest

# ======================================================
# ADD COMPLAINT
# ======================================================

@app.post("/complaints/add")
def add_complaint(
    data: ComplaintSchema,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    complaint = Complaint(
        user_id=current_user.id,
        subject=data.subject,
        message=data.message
    )

    db.add(complaint)
    db.commit()

    return {
        "message": "Complaint submitted"
    }

# ======================================================
# GET USER COMPLAINTS
# ======================================================

@app.get("/complaints/my")
def get_my_complaints(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    complaints = db.query(Complaint).filter(
        Complaint.user_id == current_user.id
    ).all()

    return complaints

# ======================================================
# RUN:
#
# uvicorn main:app --reload
#
# ======================================================
import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
