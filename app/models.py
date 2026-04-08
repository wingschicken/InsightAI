from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Boolean, create_engine, inspect, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from datetime import datetime
from werkzeug.security import generate_password_hash

DATABASE_URL = 'sqlite:///users.db'
engine = create_engine(DATABASE_URL, connect_args={'check_same_thread': False})
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
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    user = relationship('User', back_populates='scans')

Base.metadata.create_all(bind=engine)


def ensure_columns():
    inspector = inspect(engine)
    if 'users' not in inspector.get_table_names():
        return

    existing = [col['name'] for col in inspector.get_columns('users')]
    with engine.connect() as conn:
        if 'email' not in existing:
            conn.execute(text("ALTER TABLE users ADD COLUMN email VARCHAR"))
        if 'display_name' not in existing:
            conn.execute(text("ALTER TABLE users ADD COLUMN display_name VARCHAR"))
        if 'avatar_url' not in existing:
            conn.execute(text("ALTER TABLE users ADD COLUMN avatar_url VARCHAR"))
        if 'theme' not in existing:
            conn.execute(text("ALTER TABLE users ADD COLUMN theme VARCHAR DEFAULT 'dark'"))
        if 'preferred_profile' not in existing:
            conn.execute(text("ALTER TABLE users ADD COLUMN preferred_profile VARCHAR DEFAULT 'basic'"))
        if 'default_use_ai' not in existing:
            conn.execute(text("ALTER TABLE users ADD COLUMN default_use_ai BOOLEAN DEFAULT 1"))

def create_admin_user():
    session = SessionLocal()
    try:
        if not session.query(User).filter(User.username == 'admin').first():
            hashed_password = generate_password_hash('nimda123')
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
