# SecureVault — CST4067 Cloud and Big Data Technologies

A cloud-based secure file vault with:
- **AES-256-GCM** encryption at rest
- **TLS** encryption in transit (enforced by GCP)
- **Custom ABAC policy engine** for attribute-based access control
- **BigQuery** streaming audit log and access analytics
- **Firebase Authentication** for identity management

---

## GCP Setup (do this first)

### Step 1 — Create a Google Cloud Account
1. Go to https://console.cloud.google.com
2. Sign in with a Google account
3. Click **Activate Free Trial** (requires a credit card but will not charge; $300 credit for 90 days)

### Step 2 — Create a Project
1. Click the project dropdown at the top → **New Project**
2. Name it `secure-vault-cst4067`
3. Note your **Project ID** (shown below the name field)

### Step 3 — Enable APIs
Go to **APIs & Services → Library** and enable each of these:
- Cloud Storage API
- Cloud Firestore API
- BigQuery API
- Identity and Access Management (IAM) API

### Step 4 — Set Up Firebase
1. Go to https://firebase.google.com
2. Click **Get started** → **Add project** → select your existing GCP project
3. Go to **Authentication → Sign-in method → Email/Password → Enable**
4. Go to **Project Settings → General** and copy the **Web API Key** (starts with `AIza...`)

### Step 5 — Create a Service Account
1. In GCP Console: **IAM & Admin → Service Accounts → Create Service Account**
2. Name: `secure-vault-sa`
3. Grant these roles:
   - Storage Admin
   - Cloud Datastore User
   - BigQuery Data Editor
   - BigQuery Job User
4. Click **Done**, then click the service account → **Keys → Add Key → JSON**
5. A JSON file downloads — rename it to `serviceaccount.json` and place it in this folder

### Step 6 — Create a GCS Bucket
1. **Cloud Storage → Create bucket**
2. Choose a globally unique name (e.g. `secure-vault-files-abc123`)
3. Region: `us-central1` (or nearest to you)
4. Storage class: **Standard**
5. Leave all other settings default

### Step 7 — Create a Firestore Database
1. **Firestore → Create database**
2. Choose **Native mode**
3. Location: `us-central1` (same as bucket)

---

## Local Setup

```bash
# Clone or unzip the project
cd secure-vault

# Create virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy .env.example and fill in your values
cp .env.example .env
# Edit .env with your Project ID, bucket name, Firebase API key, etc.
```

### .env values to fill in

| Variable | Where to find it |
|----------|-----------------|
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to `serviceaccount.json` |
| `GCP_PROJECT_ID` | GCP Console dashboard — shown under project name |
| `GCS_BUCKET_NAME` | Name you gave the bucket in Step 6 |
| `FIREBASE_API_KEY` | Firebase Console → Project Settings → General → Web API Key |
| `FLASK_SECRET_KEY` | Any long random string |

---

## Initialise Data (run once)

```bash
# Create BigQuery dataset and table
python setup_bigquery.py

# Create test users in Firebase Auth + Firestore, and seed ABAC policies
python seed_data.py
```

---

## Run the App

```bash
python app.py
```

Open http://localhost:5000 in your browser.

---

## Test Credentials

| Email | Password | Department | Clearance | Access |
|-------|----------|-----------|-----------|--------|
| admin@vault.com | Admin@1234 | Admin | 5 | Full admin panel |
| alice@vault.com | Alice@1234 | Finance | 3 | finance_read + finance_full |
| carol@vault.com | Carol@1234 | Finance | 1 | finance_read only |
| bob@vault.com   | Bob@1234   | HR      | 2 | Public files only |

---

## Demo Scenarios for the Video

1. **Login as admin** → upload a file with `finance_full` policy
2. **Login as alice** (Finance, L3) → can download the file ✓
3. **Login as carol** (Finance, L1) → access denied ✗ (clearance too low)
4. **Login as bob** (HR, L2) → access denied ✗ (wrong department)
5. **Admin panel → edit carol's clearance to 3** → carol can now download ✓
6. **Admin → Analytics** → show BigQuery table with all events, denials flagged

---

## Architecture

```
User (Browser)
    │
    ▼
Flask Backend (app.py)
    │
    ├── Firebase Auth REST API  — login, get JWT
    ├── Firebase Admin SDK      — verify JWT
    │
    ├── ABAC Engine (abac_engine.py)
    │       └── Firestore: users / files / policies
    │
    ├── AES-256-GCM (encryption.py)
    │       └── Google Cloud Storage (encrypted blobs)
    │
    └── BigQuery Logger (bigquery_logger.py)
            └── BigQuery: file_vault_audit.access_events
```

---

## File Structure

```
secure-vault/
├── app.py                Flask application and all routes
├── abac_engine.py        Custom ABAC policy evaluation engine
├── encryption.py         AES-256-GCM encrypt / decrypt
├── bigquery_logger.py    BigQuery streaming insert + analytics queries
├── seed_data.py          One-time setup: users + policies
├── setup_bigquery.py     One-time setup: BigQuery table
├── requirements.txt
├── .env.example
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── dashboard.html
│   ├── admin.html
│   └── analytics.html
└── static/
    └── style.css
```
