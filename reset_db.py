import os
from app import app, db

def reset_database():
    db_path = os.path.join('instance', 'users.db')
    if os.path.exists(db_path):
        os.remove(db_path)
        print(f"Deleted {db_path}")
    else:
        print(f"{db_path} does not exist")

    with app.app_context():
        db.create_all()
        print("Created new database tables")

if __name__ == "__main__":
    reset_database()
