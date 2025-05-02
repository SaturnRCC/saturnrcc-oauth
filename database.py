import os
import uuid
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime, timedelta

# Database connection URL
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://user:password@localhost/oauthdb")

# SQLAlchemy Engine
engine = create_engine(DATABASE_URL)

# SQLAlchemy SessionLocal
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for declarative models
Base = declarative_base()

# Dependency to get the database session
def get_db():
   db = SessionLocal()
   try:
       yield db
   finally:
       db.close()

# --- Database Models ---

class User(Base):
   __tablename__ = "users"

   id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4())) # Use String for UUID
   email = Column(String, unique=True, index=True)
   name = Column(String)
   hashed_password = Column(String)

   authorization_codes = relationship("AuthorizationCode", back_populates="user")
   access_tokens = relationship("AccessToken", back_populates="user")

class OAuthClient(Base):
   __tablename__ = "oauth_clients"

   id = Column(Integer, primary_key=True, index=True)
   client_id = Column(String, unique=True, index=True)
   client_secret = Column(String)
   redirect_uri = Column(String)

   authorization_codes = relationship("AuthorizationCode", back_populates="client")
   access_tokens = relationship("AccessToken", back_populates="client")

class AuthorizationCode(Base):
   __tablename__ = "authorization_codes"

   id = Column(Integer, primary_key=True, index=True)
   code = Column(String, unique=True, index=True)
   user_id = Column(String, ForeignKey("users.id")) # Update foreign key type
   client_id = Column(Integer, ForeignKey("oauth_clients.id"))
   expires_at = Column(DateTime)
   is_used = Column(Boolean, default=False)

   user = relationship("User", back_populates="authorization_codes")
   client = relationship("OAuthClient", back_populates="authorization_codes")

class AccessToken(Base):
   __tablename__ = "access_tokens"

   id = Column(Integer, primary_key=True, index=True)
   token = Column(String, unique=True, index=True) # If using JWT, this might store the token string
   user_id = Column(String, ForeignKey("users.id")) # Update foreign key type
   client_id = Column(Integer, ForeignKey("oauth_clients.id"))
   expires_at = Column(DateTime)

   user = relationship("User", back_populates="access_tokens")
   client = relationship("OAuthClient", back_populates="access_tokens")

# Create database tables (for initial setup, migrations are recommended for production)
# Base.metadata.create_all(bind=engine)