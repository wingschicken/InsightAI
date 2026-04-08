from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Boolean, create_engine, inspect, text
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from datetime import datetime
from werkzeug.security import generate_password_hash
import os

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:////tmp/app.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    email = Column(String, nullable=True, default='')
    display_name = Column(String, nullable=True, default='')
    avatar_url = Column(String, nullable=True, default='')
    theme = Column(String, nullable=False, default='dark')
    preferred_profile = Column(String, nullable=False, default='basic')
    default_use_ai = Column(Boolean, nullable=False, default=True)
    scans = relationship('ScanHistory', back_populates='user', cascade='all, delete-orphan')


class ScanHistory(Base):
    __tablename__ = 'scan_history'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    target = Column(String, nullable=False)
    profile = Column(String, nullable=False)
    web_scan = Column(Boolean, nullable=False, default=True)
    use_ai = Column(Boolean, nullable=False, default=True)
    result = Column(String, nullable=False)
    duration = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    user = relationship('User', back_populates='scans')


Base.metadata.create_all(bind=engine)


def ensure_columns():
    inspector = inspect(engine)
    table_names = inspector.get_table_names()

    if 'users' not in table_names:
        return

    existing = [col['name'] for col in inspector.get_columns('users')]
    with engine.connect() as conn:
        changed = False
        if 'email' not in existing:
            conn.execute(text("ALTER TABLE users ADD COLUMN email VARCHAR"))
            changed = True
        if 'display_name' not in existing:
            conn.execute(text("ALTER TABLE users ADD COLUMN display_name VARCHAR"))
            changed = True
        if 'avatar_url' not in existing:
            conn.execute(text("ALTER TABLE users ADD COLUMN avatar_url VARCHAR"))
            changed = True
        if 'theme' not in existing:
            conn.execute(text("ALTER TABLE users ADD COLUMN theme VARCHAR DEFAULT 'dark'"))
            changed = True
        if 'preferred_profile' not in existing:
            conn.execute(text("ALTER TABLE users ADD COLUMN preferred_profile VARCHAR DEFAULT 'basic'"))
            changed = True
        if 'default_use_ai' not in existing:
            conn.execute(text("ALTER TABLE users ADD COLUMN default_use_ai BOOLEAN DEFAULT 1"))
            changed = True
        if changed:
            conn.commit()

    if 'scan_history' in table_names:
        scan_history_cols = [col['name'] for col in inspector.get_columns('scan_history')]
        with engine.connect() as conn:
            changed = False
            if 'duration' not in scan_history_cols:
                conn.execute(text("ALTER TABLE scan_history ADD COLUMN duration INTEGER DEFAULT 0"))
                changed = True
            if changed:
                conn.commit()


def create_admin_user():
    session = SessionLocal()
    try:
        if not session.query(User).filter(User.username == 'admin').first():
            admin_password = os.environ.get("ADMIN_PASSWORD", "nimda123")
            hashed_password = generate_password_hash(admin_password)
            admin = User(
                username='admin',
                password=hashed_password,
                email='admin@example.com',
                display_name='Admin',
                theme='dark',
                preferred_profile='basic',
                default_use_ai=True,
            )
            session.add(admin)
            session.commit()
    finally:
        session.close()


ensure_columns()
create_admin_user()
