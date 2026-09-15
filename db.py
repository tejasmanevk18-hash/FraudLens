"""
db.py — MySQL connection and helper functions for FraudLens.

Connects to the MySQL database 'fraudlens_new' used by the app.
All database operations are centralized here for maintainability.
"""

import os
import traceback

import mysql.connector
from mysql.connector import Error as MySQLError


class DatabaseUnavailableError(MySQLError):
    """Raised when the application cannot reach the configured MySQL server."""


# MySQL connection configuration
#
# Use environment variables for hosted deployment while keeping the
# existing local defaults and MYSQL_* compatibility as fallbacks.
DB_CONFIG = {
    "host": os.environ.get("DB_HOST") or os.environ.get("MYSQL_HOST", "127.0.0.1"),
    "user": os.environ.get("DB_USER") or os.environ.get("MYSQL_USER", "root"),
    "password": os.environ.get("DB_PASSWORD") or os.environ.get("MYSQL_PASSWORD", "Fraudlens@123"),
    "database": os.environ.get("DB_NAME") or os.environ.get("MYSQL_DATABASE", "fraudlens_new"),
    "port": int(os.environ.get("DB_PORT") or os.environ.get("MYSQL_PORT", "3306")),
}

# Debug: Show connection info (without password)
print(f"[DB] MySQL Host: {DB_CONFIG['host']}")
print(f"[DB] MySQL User: {DB_CONFIG['user']}")
print(f"[DB] MySQL Port: {DB_CONFIG['port']}")
print(f"[DB] MySQL Database: {DB_CONFIG['database']}")
print(f"[DB] MySQL Connection Configured")


def get_db_connection():
    """
    Create and return a new MySQL database connection.
    
    Returns:
        connection: MySQL connection object
        
    Raises:
        MySQLError: If connection fails
    """
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        if connection.is_connected():
            return connection
    except MySQLError as e:
        raise DatabaseUnavailableError(
            f"Failed to connect to MySQL at {DB_CONFIG['host']}:{DB_CONFIG['port']}: {e}"
        ) from e


def check_user_by_email(email):
    """
    Check if a user exists by email.
    
    Args:
        email (str): User's email address
        
    Returns:
        dict: User data if found, None otherwise
    """
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, full_name, email, password, is_active, created_at FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        return user
    except DatabaseUnavailableError:
        raise
    except MySQLError as e:
        print(f"Database error in check_user_by_email: {e}")
        traceback.print_exc()
        return None
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


def create_user(full_name, email, password_hash):
    """
    Create a new user in the database.
    
    Args:
        full_name (str): User's full name
        email (str): User's email address (unique)
        password_hash (str): Hashed password
        
    Returns:
        dict: Created user data with id, or None if failed
    """
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Insert new user
        cursor.execute(
            "INSERT INTO users (full_name, email, password) VALUES (%s, %s, %s)",
            (full_name, email, password_hash)
        )
        conn.commit()
        
        # Retrieve the created user
        user_id = cursor.lastrowid
        cursor.execute(
            "SELECT id, full_name, email, is_active, created_at FROM users WHERE id = %s",
            (user_id,)
        )
        user = cursor.fetchone()
        return user
        
    except DatabaseUnavailableError:
        raise
    except MySQLError as e:
        if conn:
            conn.rollback()
        print(f"Database error in create_user: {e}")
        traceback.print_exc()
        return None
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


def get_user_by_id(user_id):
    """
    Retrieve user by ID.
    
    Args:
        user_id (int): User's ID
        
    Returns:
        dict: User data if found, None otherwise
    """
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, full_name, email, is_active, created_at FROM users WHERE id = %s",
            (user_id,)
        )
        user = cursor.fetchone()
        return user
    except MySQLError as e:
        print(f"Database error in get_user_by_id: {e}")
        traceback.print_exc()
        return None
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


def get_all_users():
    """
    Retrieve all users from the database.
    
    Returns:
        list: List of user dictionaries, empty list if none or error
    """
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, full_name, email, is_active, created_at FROM users ORDER BY created_at DESC")
        users = cursor.fetchall()
        return users if users else []
    except MySQLError as e:
        print(f"Database error in get_all_users: {e}")
        traceback.print_exc()
        return []
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


def _insert_scan(sql, values):
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(sql, values)
        conn.commit()
        return True
    except MySQLError as e:
        if conn:
            conn.rollback()
        print(f"Database error while saving scan: {e}")
        return False
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


def save_sms_scan(user_id, message, result, risk_score):
    return _insert_scan(
        "INSERT INTO sms_scans (user_id, message, result, risk_score) VALUES (%s, %s, %s, %s)",
        (user_id, message, result, risk_score)
    )


def save_link_scan(user_id, url, result, risk_score):
    return _insert_scan(
        "INSERT INTO link_scans (user_id, url, result, risk_score) VALUES (%s, %s, %s, %s)",
        (user_id, url, result, risk_score)
    )


def save_qr_scan(user_id, qr_content, result, risk_score):
    return _insert_scan(
        "INSERT INTO qr_scans (user_id, qr_content, result, risk_score) VALUES (%s, %s, %s, %s)",
        (user_id, qr_content, result, risk_score)
    )


def get_scan_history(user_id, limit=10):
    """Return only this user's latest scans across all scan tables."""
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT scan_type, input_value, result, risk_score, created_at
            FROM (
                SELECT 'SMS Scan' AS scan_type, message AS input_value, result, risk_score, created_at
                FROM sms_scans WHERE user_id = %s
                UNION ALL
                SELECT 'Link Check', url, result, risk_score, created_at
                FROM link_scans WHERE user_id = %s
                UNION ALL
                SELECT 'QR Scan', qr_content, result, risk_score, created_at
                FROM qr_scans WHERE user_id = %s
            ) AS scan_history
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (user_id, user_id, user_id, limit)
        )
        return cursor.fetchall() or []
    except MySQLError as e:
        print(f"Database error while reading scan history: {e}")
        return []
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


def get_scan_stats(user_id):
    """Return aggregate counts for only this user's scans."""
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT COUNT(*) AS total,
                   COALESCE(SUM(CASE WHEN risk_score >= 40 THEN 1 ELSE 0 END), 0) AS threats,
                   COALESCE(SUM(CASE WHEN risk_score < 40 THEN 1 ELSE 0 END), 0) AS safe,
                   COALESCE(AVG(risk_score), 0) AS average_risk
            FROM (
                SELECT risk_score FROM sms_scans WHERE user_id = %s
                UNION ALL
                SELECT risk_score FROM link_scans WHERE user_id = %s
                UNION ALL
                SELECT risk_score FROM qr_scans WHERE user_id = %s
            ) AS user_scans
            """,
            (user_id, user_id, user_id)
        )
        row = cursor.fetchone() or {}
        total = int(row.get("total") or 0)
        average_risk = float(row.get("average_risk") or 0)
        risk_level = "High" if average_risk >= 70 else "Medium" if average_risk >= 40 else "Low"
        return {
            "total": total,
            "threats": int(row.get("threats") or 0),
            "safe": int(row.get("safe") or 0),
            "average_risk": average_risk,
            "risk_level": risk_level if total else "No data"
        }
    except MySQLError as e:
        print(f"Database error while reading scan stats: {e}")
        return {"total": 0, "threats": 0, "safe": 0, "average_risk": 0, "risk_level": "No data"}
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()