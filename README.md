# 🔍 Git Secret Scanner

A powerful full-stack application to scan Git repositories for exposed secrets, tokens, passwords, and confidential values across **all branches** and **entire commit history**.

![Git Secret Scanner](https://img.shields.io/badge/Security-Secret%20Scanner-00d4ff?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.9+-00ff88?style=for-the-badge)
![React](https://img.shields.io/badge/React-18-61dafb?style=for-the-badge)

## ✨ Features

- 🌿 **Scan All Branches** - Automatically detects and scans every branch in the repository
- 📜 **Full History Analysis** - Scans through entire git commit history, not just current HEAD
- 🔐 **50+ Secret Patterns** - Detects AWS keys, API tokens, private keys, database credentials, and more
- ⚡ **Fast & Efficient** - Background processing with real-time progress updates
- 🎨 **Modern UI** - Beautiful cyberpunk-themed dark interface
- 📊 **Severity Classification** - Categorizes findings as Critical, High, Medium, or Low
- 🔒 **Safe Masking** - Secrets are automatically masked in the results

## 🎯 What It Detects

| Category | Examples |
|----------|----------|
| **Cloud Provider Keys** | AWS Access Keys, Azure Storage Keys, GCP API Keys |
| **API Tokens** | GitHub, Slack, Stripe, SendGrid, Twilio, Discord |
| **Private Keys** | RSA, OpenSSH, DSA, EC, PGP private keys |
| **Database Credentials** | MongoDB, PostgreSQL, MySQL, Redis connection strings |
| **Generic Secrets** | Passwords, API keys, tokens, auth headers, JWTs |

## 🚀 Quick Start

### Prerequisites

- **Python 3.9+** with pip
- **Node.js 18+** with npm
- **Git** installed and available in PATH

### 1. Clone & Setup Backend

```bash
cd Git_Scrapper/backend

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start the backend server
python app.py
```

The backend will run at `http://localhost:8000`

### 2. Setup Frontend

```bash
cd Git_Scrapper/frontend

# Install dependencies
npm install

# Start the development server
npm run dev
```

The frontend will run at `http://localhost:3000`

### 3. Use the Application

1. Open `http://localhost:3000` in your browser
2. Paste a public Git repository URL
3. Click "Scan Repository"
4. Wait for the scan to complete
5. Review the findings with severity levels and details

## 📡 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scan` | POST | Start a new repository scan |
| `/api/scan/{scan_id}` | GET | Get scan status and results |
| `/api/health` | GET | Health check |

### Example: Start a Scan

```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"git_url": "https://github.com/user/repo"}'
```

### Example: Check Status

```bash
curl http://localhost:8000/api/scan/{scan_id}
```

## 🛡️ Security Notes

- Only scan repositories you own or have permission to audit
- Never scan repositories containing real production secrets without proper authorization
- The scanner masks secrets in the output for safety
- Results are stored in-memory only (not persisted to disk)

## 🔧 Configuration

### Adding Custom Patterns

Edit `backend/app.py` and add patterns to the `SECRET_PATTERNS` list:

```python
SECRET_PATTERNS = [
    # ... existing patterns ...
    {
        "name": "My Custom Token",
        "pattern": r"my_token_[a-zA-Z0-9]{32}",
        "severity": "high"
    },
]
```

### Severity Levels

- **Critical** - Credentials that could lead to immediate compromise (AWS keys, private keys)
- **High** - API keys and tokens with significant access
- **Medium** - Tokens with limited scope or publishable keys
- **Low** - Potentially sensitive but low-risk findings

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     React Frontend                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ URL Input    │  │ Progress UI  │  │ Results Display  │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    FastAPI Backend                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ Clone Repo   │  │ Scan Engine  │  │ Pattern Matcher  │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## 📝 License

MIT License - Feel free to use, modify, and distribute.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Always obtain proper authorization before scanning repositories. The authors are not responsible for any misuse of this tool.

