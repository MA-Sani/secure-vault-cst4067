"""
app.py
Secure Cloud File Vault — Flask Application
CST4067 Cloud and Big Data Technologies

Routes:
  GET  /                       → redirect to /dashboard or /login
  GET  /login                  → login page
  POST /login                  → Firebase Auth sign-in
  GET  /logout                 → clear session
  GET  /dashboard              → file list with per-file ABAC status
  POST /upload                 → encrypt + upload file to GCS
  GET  /download/<file_id>     → ABAC check → decrypt → serve file
  POST /delete/<file_id>       → ABAC check (or owner) → delete
  GET  /admin                  → admin panel (admin only)
  POST /admin/update-user      → update user's ABAC attributes
  POST /admin/assign-policy    → attach a policy to a file
  POST /admin/create-policy    → create a new ABAC policy
  GET  /analytics              → BigQuery access analytics (admin only)
"""

import io
import os
import uuid
from datetime import datetime, timezone
from functools import wraps

import requests
from dotenv import load_dotenv
from flask import (Flask, flash, redirect, render_template,
                   request, send_file, session, url_for)

import firebase_admin
from firebase_admin import auth, credentials, firestore
from google.cloud import storage

from abac_engine import ABACEngine
from bigquery_logger import BigQueryLogger
from encryption import (decrypt_file, encrypt_file, generate_key,
                         key_to_str, nonce_to_str, str_to_key, str_to_nonce)

# ──────────────────────────────────────────────────────────────
# Bootstrap
# ──────────────────────────────────────────────────────────────

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'change-me-in-production')

# Firebase Admin SDK (uses service account)
cred = credentials.Certificate(os.getenv('GOOGLE_APPLICATION_CREDENTIALS'))
firebase_admin.initialize_app(cred)

# Firestore
db = firestore.client()

# Google Cloud Storage
gcs_client = storage.Client()
bucket      = gcs_client.bucket(os.getenv('GCS_BUCKET_NAME'))

# ABAC engine
abac = ABACEngine(db)

# BigQuery audit logger
bq_logger = BigQueryLogger(os.getenv('GCP_PROJECT_ID'))

FIREBASE_API_KEY = os.getenv('FIREBASE_API_KEY')

# ──────────────────────────────────────────────────────────────
# Auth helpers
# ──────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'uid' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'uid' not in session:
            return redirect(url_for('login'))
        if not session.get('is_admin'):
            flash('Admin access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


def firebase_sign_in(email: str, password: str) -> dict:
    """Call Firebase Auth REST API to sign in and get an ID token."""
    url = (
        f"https://identitytoolkit.googleapis.com/v1/accounts"
        f":signInWithPassword?key={FIREBASE_API_KEY}"
    )
    resp = requests.post(url, json={
        'email': email,
        'password': password,
        'returnSecureToken': True,
    }, timeout=10)
    return resp.json()


def get_current_user() -> dict | None:
    uid = session.get('uid')
    if not uid:
        return None
    doc = db.collection('users').document(uid).get()
    return doc.to_dict() if doc.exists else None


def get_all_policies() -> list[dict]:
    return [
        {'id': doc.id, **doc.to_dict()}
        for doc in db.collection('policies').stream()
    ]

# ──────────────────────────────────────────────────────────────
# Routes — Auth
# ──────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'uid' in session else url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        result = firebase_sign_in(email, password)

        if 'error' in result:
            msg = result['error'].get('message', 'Authentication failed.')
            flash(f'Login failed: {msg}', 'error')
            return render_template('login.html')

        id_token = result.get('idToken')

        try:
            decoded = auth.verify_id_token(id_token)
            uid     = decoded['uid']

            user_doc  = db.collection('users').document(uid).get()
            user_data = user_doc.to_dict() if user_doc.exists else {}

            session['uid']        = uid
            session['email']      = email
            session['department'] = user_data.get('department', 'Unknown')
            session['is_admin']   = user_data.get('department', '') == 'Admin'

            return redirect(url_for('dashboard'))

        except Exception as exc:
            flash(f'Token verification failed: {exc}', 'error')
            return render_template('login.html')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ──────────────────────────────────────────────────────────────
# Routes — Dashboard
# ──────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    uid      = session['uid']
    user     = get_current_user()
    policies = get_all_policies()

    raw_files = db.collection('files').stream()
    files     = []

    for doc in raw_files:
        data            = doc.to_dict()
        data['id']      = doc.id
        allowed, reason = abac.evaluate(uid, doc.id, 'read')
        data['can_read']       = allowed
        data['access_reason']  = reason
        data['is_owner']       = data.get('owner_uid') == uid
        files.append(data)

    # Sort: owned files first, then accessible, then denied
    files.sort(key=lambda f: (0 if f['is_owner'] else 1 if f['can_read'] else 2))

    return render_template(
        'dashboard.html',
        files=files,
        user=user,
        policies=policies,
    )

# ──────────────────────────────────────────────────────────────
# Routes — File operations
# ──────────────────────────────────────────────────────────────

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    uid = session['uid']

    if 'file' not in request.files or request.files['file'].filename == '':
        flash('No file selected.', 'error')
        return redirect(url_for('dashboard'))

    uploaded = request.files['file']
    policy_id = request.form.get('policy_id', '').strip()

    raw_bytes = uploaded.read()

    # AES-256-GCM encryption
    key        = generate_key()
    ciphertext, nonce = encrypt_file(raw_bytes, key)

    # Upload encrypted blob to GCS
    file_id  = str(uuid.uuid4())
    gcs_path = f"encrypted/{file_id}"
    blob     = bucket.blob(gcs_path)
    blob.upload_from_string(ciphertext, content_type='application/octet-stream', timeout=300)

    # Store metadata in Firestore (key + nonce stored here; use Cloud KMS in production)
    db.collection('files').document(file_id).set({
        'file_name':      uploaded.filename,
        'owner_uid':      uid,
        'owner_email':    session['email'],
        'upload_date':    datetime.now(timezone.utc).isoformat(),
        'gcs_path':       gcs_path,
        'policy_id':      policy_id,
        'encryption_key': key_to_str(key),
        'nonce':          nonce_to_str(nonce),
        'size_bytes':     len(raw_bytes),
    })

    # Audit log
    bq_logger.log_event(
        user_uid=uid,
        user_department=session.get('department', 'Unknown'),
        file_id=file_id,
        action='upload',
        decision='ALLOW',
        policy_id=policy_id,
    )

    flash(f'"{uploaded.filename}" encrypted with AES-256-GCM and uploaded successfully.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/download/<file_id>')
@login_required
def download(file_id: str):
    uid = session['uid']

    # Load file metadata
    file_doc = db.collection('files').document(file_id).get()
    if not file_doc.exists:
        flash('File not found.', 'error')
        return redirect(url_for('dashboard'))

    file_data = file_doc.to_dict()

    # ABAC evaluation
    allowed, reason = abac.evaluate(uid, file_id, 'read')

    # Audit log (always log, allow or deny)
    bq_logger.log_event(
        user_uid=uid,
        user_department=session.get('department', 'Unknown'),
        file_id=file_id,
        action='read',
        decision='ALLOW' if allowed else 'DENY',
        deny_reason='' if allowed else reason,
        policy_id=file_data.get('policy_id', ''),
    )

    if not allowed:
        flash(f'Access denied — {reason}', 'error')
        return redirect(url_for('dashboard'))

    # Fetch + decrypt
    blob           = bucket.blob(file_data['gcs_path'])
    encrypted_data = blob.download_as_bytes()
    key            = str_to_key(file_data['encryption_key'])
    nonce          = str_to_nonce(file_data['nonce'])
    decrypted_data = decrypt_file(encrypted_data, key, nonce)

    return send_file(
        io.BytesIO(decrypted_data),
        download_name=file_data['file_name'],
        as_attachment=True,
    )


@app.route('/delete/<file_id>', methods=['POST'])
@login_required
def delete_file(file_id: str):
    uid = session['uid']

    file_doc = db.collection('files').document(file_id).get()
    if not file_doc.exists:
        flash('File not found.', 'error')
        return redirect(url_for('dashboard'))

    file_data = file_doc.to_dict()
    is_owner  = file_data.get('owner_uid') == uid

    # Owner can always delete their own file; others need ABAC delete permission
    if not is_owner:
        allowed, reason = abac.evaluate(uid, file_id, 'delete')
        if not allowed:
            bq_logger.log_event(
                user_uid=uid,
                user_department=session.get('department', 'Unknown'),
                file_id=file_id,
                action='delete',
                decision='DENY',
                deny_reason=reason,
                policy_id=file_data.get('policy_id', ''),
            )
            flash(f'Access denied — {reason}', 'error')
            return redirect(url_for('dashboard'))

    # Delete from GCS
    bucket.blob(file_data['gcs_path']).delete()

    # Delete from Firestore
    db.collection('files').document(file_id).delete()

    bq_logger.log_event(
        user_uid=uid,
        user_department=session.get('department', 'Unknown'),
        file_id=file_id,
        action='delete',
        decision='ALLOW',
        policy_id=file_data.get('policy_id', ''),
    )

    flash('File deleted.', 'success')
    return redirect(url_for('dashboard'))

# ──────────────────────────────────────────────────────────────
# Routes — Admin
# ──────────────────────────────────────────────────────────────

@app.route('/admin')
@admin_required
def admin():
    users    = [{'id': d.id, **d.to_dict()} for d in db.collection('users').stream()]
    policies = [{'id': d.id, **d.to_dict()} for d in db.collection('policies').stream()]
    files    = [{'id': d.id, **d.to_dict()} for d in db.collection('files').stream()]
    tab      = request.args.get('tab', 'users')
    return render_template('admin.html', users=users, policies=policies, files=files, tab=tab)


@app.route('/admin/update-user', methods=['POST'])
@admin_required
def update_user():
    user_id        = request.form.get('user_id')
    department     = request.form.get('department', '').strip()
    clearance_level = int(request.form.get('clearance_level', 1))

    db.collection('users').document(user_id).update({
        'department':     department,
        'clearance_level': clearance_level,
    })

    flash(f'User attributes updated.', 'success')
    return redirect(url_for('admin', tab='users'))


@app.route('/admin/assign-policy', methods=['POST'])
@admin_required
def assign_policy():
    file_id   = request.form.get('file_id')
    policy_id = request.form.get('policy_id', '').strip()

    db.collection('files').document(file_id).update({'policy_id': policy_id})

    flash('Policy assigned to file.', 'success')
    return redirect(url_for('admin', tab='files'))


@app.route('/admin/create-policy', methods=['POST'])
@admin_required
def create_policy():
    policy_name       = request.form.get('policy_name', '').strip()
    department        = request.form.get('department', '').strip()
    min_clearance     = request.form.get('min_clearance', '').strip()
    permitted_actions = request.form.getlist('permitted_actions')

    if not policy_name:
        flash('Policy name is required.', 'error')
        return redirect(url_for('admin', tab='policies'))

    conditions = []
    if department:
        conditions.append({
            'attribute': 'department',
            'operator':  'equals',
            'value':     department,
        })
    if min_clearance:
        conditions.append({
            'attribute': 'clearance_level',
            'operator':  'gte',
            'value':     int(min_clearance),
        })

    policy_id = str(uuid.uuid4())[:8]   # Short readable ID
    db.collection('policies').document(policy_id).set({
        'policy_name':      policy_name,
        'conditions':       conditions,
        'permitted_actions': permitted_actions,
        'created_at':       datetime.now(timezone.utc).isoformat(),
    })

    flash(f'Policy "{policy_name}" created.', 'success')
    return redirect(url_for('admin', tab='policies'))

# ──────────────────────────────────────────────────────────────
# Routes — Analytics
# ──────────────────────────────────────────────────────────────

@app.route('/analytics')
@admin_required
def analytics():
    data  = {}
    error = None
    try:
        data = bq_logger.get_analytics()
    except Exception as exc:
        error = str(exc)
    return render_template('analytics.html', data=data, error=error)

# ──────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
