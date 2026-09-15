#!/usr/bin/env python
"""Verify users in MySQL database using the exact query from requirements"""

from db import get_db_connection

print("\n" + "="*70)
print("MySQL Database Verification")
print("="*70 + "\n")

print("Running query: SELECT * FROM fraudlens.users;\n")

try:
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT * FROM fraudlens.users")
    users = cursor.fetchall()
    
    if users:
        print(f"Found {len(users)} user(s) in database:\n")
        for user in users:
            print(f"  ID: {user['id']}")
            print(f"  Full Name: {user['full_name']}")
            print(f"  Email: {user['email']}")
            print(f"  Password (hash): {user['password'][:20]}... (truncated)")
            print(f"  Is Active: {user['is_active']}")
            print(f"  Created At: {user['created_at']}")
            print()
    else:
        print("No users found in database")
    
    cursor.close()
    conn.close()
    
    print("="*70)
    print("✓ Database verification complete")
    print("="*70 + "\n")
    
except Exception as e:
    print(f"✗ Error verifying database: {e}")
    import traceback
    traceback.print_exc()
