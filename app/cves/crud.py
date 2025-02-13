from sqlalchemy.orm import Session
from app.users.models import User


# Создание пользователя
def create_user(db: Session, name: str, email: str, age: int):
    new_user = User(name=name, email=email, age=age)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


# Получение пользователя по ID
def get_user(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()


# Удаление пользователя
def delete_user(db: Session, user_id: int):
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        db.delete(user)
        db.commit()