"""
seed_data.py
Run this ONCE after GCP setup to create test users and ABAC policies.

Usage:
    python seed_data.py

Creates 4 Firebase Auth users + Firestore profiles and 4 ABAC policies.
Demo scenarios these users enable:
  - alice (Finance, L3) → CAN access finance_read and finance_full files
  - carol (Finance, L1) → can access finance_read but NOT finance_full
  - bob   (HR,      L2) → CANNOT access any finance files (wrong dept)
  - admin (Admin,   L5) → admin panel access, can manage everything
"""

import os
from dotenv import load_dotenv
import firebase_admin
from firebase_admin import auth, credentials, firestore

load_dotenv()

cred = credentials.Certificate(os.getenv('GOOGLE_APPLICATION_CREDENTIALS'))
firebase_admin.initialize_app(cred)
db = firestore.client()

# ──────────────────────────────────────────────────────────────
# Test users
# ──────────────────────────────────────────────────────────────

USERS = [
    {
        'email':          'admin@vault.com',
        'password':       'Admin@1234',
        'name':           'Admin User',
        'department':     'Admin',
        'clearance_level': 5,
    },
    {
        'email':          'alice@vault.com',
        'password':       'Alice@1234',
        'name':           'Alice Chen',
        'department':     'Finance',
        'clearance_level': 3,
    },
    {
        'email':          'carol@vault.com',
        'password':       'Carol@1234',
        'name':           'Carol Jones',
        'department':     'Finance',
        'clearance_level': 1,
    },
    {
        'email':          'bob@vault.com',
        'password':       'Bob@1234',
        'name':           'Bob Smith',
        'department':     'HR',
        'clearance_level': 2,
    },
]

# ──────────────────────────────────────────────────────────────
# ABAC Policies
# ──────────────────────────────────────────────────────────────

POLICIES = [
    {
        'id': 'public',
        'policy_name':       'Public Access',
        'conditions':        [],            # No conditions = any authenticated user
        'permitted_actions': ['read'],
        'description':       'Any logged-in user can read.',
    },
    {
        'id': 'finance_read',
        'policy_name': 'Finance Read (Clearance 1+)',
        'conditions': [
            {'attribute': 'department', 'operator': 'equals', 'value': 'Finance'},
            {'attribute': 'clearance_level', 'operator': 'gte', 'value': 1},
        ],
        'permitted_actions': ['read'],
        'description': 'Finance dept, any clearance level, read-only.',
    },
    {
        'id': 'finance_full',
        'policy_name': 'Finance Full Access (Clearance 3+)',
        'conditions': [
            {'attribute': 'department', 'operator': 'equals', 'value': 'Finance'},
            {'attribute': 'clearance_level', 'operator': 'gte', 'value': 3},
        ],
        'permitted_actions': ['read', 'write', 'delete'],
        'description': 'Finance dept, clearance 3 or above, full access.',
    },
    {
        'id': 'admin_only',
        'policy_name': 'Admin Only',
        'conditions': [
            {'attribute': 'department', 'operator': 'equals', 'value': 'Admin'},
        ],
        'permitted_actions': ['read', 'write', 'delete'],
        'description': 'Admin department only.',
    },
]

# ──────────────────────────────────────────────────────────────
# Run
# ──────────────────────────────────────────────────────────────

def main():
    print("=" * 55)
    print("  CST4067 SecureVault — Seed Script")
    print("=" * 55)

    print("\n[1/2] Creating Firebase Auth users + Firestore profiles...")
    for u in USERS:
        try:
            fb_user = auth.create_user(email=u['email'], password=u['password'])
            uid     = fb_user.uid
            db.collection('users').document(uid).set({
                'name':           u['name'],
                'email':          u['email'],
                'department':     u['department'],
                'clearance_level': u['clearance_level'],
            })
            print(f"  ✓  {u['email']} | {u['department']}, CL={u['clearance_level']} | uid={uid[:12]}…")
        except Exception as exc:
            print(f"  ✗  {u['email']}: {exc}")

    print("\n[2/2] Creating ABAC policies...")
    for p in POLICIES:
        pid = p.pop('id')
        try:
            db.collection('policies').document(pid).set(p)
            print(f"  ✓  {pid}: {p['policy_name']}")
        except Exception as exc:
            print(f"  ✗  {pid}: {exc}")

    print("\n" + "=" * 55)
    print("  Seed complete!")
    print("=" * 55)
    print("\nTest credentials:")
    for u in USERS:
        tag = "  (ADMIN)" if u['department'] == 'Admin' else ''
        print(f"  {u['email']:28} {u['password']:16} dept={u['department']}, CL={u['clearance_level']}{tag}")

    print("\nDemo scenarios:")
    print("  alice can access finance_read AND finance_full files")
    print("  carol can access finance_read but NOT finance_full (CL too low)")
    print("  bob   cannot access any finance files (wrong department)")
    print("  admin has full admin panel access\n")


if __name__ == '__main__':
    main()
