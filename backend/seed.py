# FILE: backend/seed.py
# PURPOSE: Seed the database with demo users and XSS-payload comments
# SECURITY NOTE: Stores plain-text passwords deliberately for SQL injection demo;
#                NEVER do this in production

import asyncio
import bcrypt
from sqlalchemy import text

from database import engine, AsyncSessionLocal, Base
from models.user import User
from models.comment import Comment


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


async def seed() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as session:
        await session.execute(text("DELETE FROM comments"))
        await session.execute(text("DELETE FROM users"))
        await session.commit()

        users = [
            User(
                username="admin",
                password_plain="admin123",
                password_hash=hash_password("admin123"),
                role="admin",
            ),
            User(
                username="alice",
                password_plain="password",
                password_hash=hash_password("password"),
                role="user",
            ),
            User(
                username="bob",
                password_plain="test",
                password_hash=hash_password("test"),
                role="user",
            ),
        ]
        session.add_all(users)
        await session.flush()

        comments = [
            Comment(user_id=users[1].id, content="Hello, this is a normal comment!"),
            Comment(user_id=users[2].id, content="Learning about web security is important."),
            Comment(user_id=users[0].id, content="Welcome to VulnLab — toggle modes above."),
            Comment(user_id=users[1].id, content="<script>alert('XSS Demo!')</script>"),
            Comment(user_id=users[2].id, content='<img src=x onerror=alert(document.cookie)>'),
        ]
        session.add_all(comments)
        await session.commit()

    print("Seeded successfully")


if __name__ == "__main__":
    asyncio.run(seed())
