from db import get_connection
from flask_login import UserMixin


class User(UserMixin):
    def __init__(self, id, username, password_hash, role, is_active=True, created_at=None, last_login=None):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role = role
        # Avoid clashing with UserMixin's is_active property by using a private attribute
        self._is_active = bool(is_active)
        self.created_at = created_at
        self.last_login = last_login

    @property
    def is_active(self):
        return self._is_active

    # def get_id(self):
    #     return str(self.id)


def get_user_by_username(username):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
    row = cursor.fetchone()

    cursor.close()
    conn.close()

    if row:
        return User(
            row["id"],
            row["username"],
            row["password_hash"],
            row.get("role"),
            row.get("is_active", 1),
            row.get("created_at"),
            row.get("last_login")
        )
    return None


def get_user_by_id(user_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
    row = cursor.fetchone()

    cursor.close()
    conn.close()

    if row:
        return User(
            row["id"],
            row["username"],
            row["password_hash"],
            row.get("role"),
            row.get("is_active", 1),
            row.get("created_at"),
            row.get("last_login")
        )
    return None
