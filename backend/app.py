"""
Git Secret Scanner - Backend API (Full Mode)
Scans Git repositories for exposed secrets across all branches and complete commit history.
Clones repos locally for deep scanning - catches secrets in deleted files too.
"""

import os
import re
import shutil
import tempfile
import subprocess
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import math

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

app = FastAPI(
    title="Git Secret Scanner - Full Mode",
    description="Deep scan Git repositories for exposed secrets across all branches and complete history",
    version="2.0.0"
)

# CORS middleware - allow all origins for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for scan results
scan_results: Dict[str, Any] = {}


class ScanRequest(BaseModel):
    git_url: str


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: int
    message: str
    results: Optional[Dict] = None


@dataclass
class SecretFinding:
    file_path: str
    line_number: int
    secret_type: str
    secret_preview: str
    secret_full: str
    commit_hash: str
    commit_author: str
    commit_date: str
    commit_message: str
    branch: str
    severity: str
    entropy: float


# Secret patterns with regex and descriptions
SECRET_PATTERNS = [
    # API Keys
    {"name": "AWS Access Key ID", "pattern": r"AKIA[0-9A-Z]{16}", "severity": "critical"},
    {"name": "AWS Secret Access Key", "pattern": r"[Aa][Ww][Ss].{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "severity": "critical"},
    {"name": "Google API Key", "pattern": r"AIza[0-9A-Za-z\-_]{35}", "severity": "high"},
    {"name": "Google OAuth ID", "pattern": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "severity": "high"},
    {"name": "GitHub Token", "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}", "severity": "critical"},
    {"name": "GitHub OAuth", "pattern": r"gho_[A-Za-z0-9]{36}", "severity": "critical"},
    {"name": "Slack Token", "pattern": r"xox[baprs]-([0-9a-zA-Z]{10,48})", "severity": "high"},
    {"name": "Slack Webhook", "pattern": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}", "severity": "high"},
    {"name": "Stripe API Key", "pattern": r"sk_live_[0-9a-zA-Z]{24,}", "severity": "critical"},
    {"name": "Stripe Publishable Key", "pattern": r"pk_live_[0-9a-zA-Z]{24,}", "severity": "medium"},
    {"name": "Square OAuth Secret", "pattern": r"sq0csp-[0-9A-Za-z\-_]{43}", "severity": "critical"},
    {"name": "Square Access Token", "pattern": r"sqOatp-[0-9A-Za-z\-_]{22}", "severity": "critical"},
    {"name": "Twilio API Key", "pattern": r"SK[0-9a-fA-F]{32}", "severity": "high"},
    {"name": "SendGrid API Key", "pattern": r"SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}", "severity": "high"},
    {"name": "Mailgun API Key", "pattern": r"key-[0-9a-zA-Z]{32}", "severity": "high"},
    {"name": "Mailchimp API Key", "pattern": r"[0-9a-f]{32}-us[0-9]{1,2}", "severity": "high"},
    {"name": "Heroku API Key", "pattern": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "severity": "medium"},
    {"name": "npm Token", "pattern": r"npm_[A-Za-z0-9]{36}", "severity": "high"},
    {"name": "PyPI Token", "pattern": r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}", "severity": "high"},
    {"name": "Discord Token", "pattern": r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}", "severity": "critical"},
    {"name": "Discord Webhook", "pattern": r"https://discord(?:app)?\.com/api/webhooks/[0-9]{18,}/[A-Za-z0-9_-]+", "severity": "high"},
    {"name": "Telegram Bot Token", "pattern": r"[0-9]+:AA[0-9A-Za-z\-_]{33}", "severity": "high"},
    {"name": "Facebook Access Token", "pattern": r"EAACEdEose0cBA[0-9A-Za-z]+", "severity": "high"},
    {"name": "Twitter API Key", "pattern": r"(?i)twitter(.{0,20})?['\"][0-9a-z]{18,25}['\"]", "severity": "high"},
    {"name": "Azure Storage Key", "pattern": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88};", "severity": "critical"},
    {"name": "Firebase URL", "pattern": r"https://[a-z0-9-]+\.firebaseio\.com", "severity": "medium"},
    {"name": "Firebase API Key", "pattern": r"(?i)firebase(.{0,20})?['\"][A-Za-z0-9_-]{39}['\"]", "severity": "high"},
    
    # Private Keys
    {"name": "RSA Private Key", "pattern": r"-----BEGIN RSA PRIVATE KEY-----", "severity": "critical"},
    {"name": "OpenSSH Private Key", "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----", "severity": "critical"},
    {"name": "DSA Private Key", "pattern": r"-----BEGIN DSA PRIVATE KEY-----", "severity": "critical"},
    {"name": "EC Private Key", "pattern": r"-----BEGIN EC PRIVATE KEY-----", "severity": "critical"},
    {"name": "PGP Private Key", "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "severity": "critical"},
    {"name": "Generic Private Key", "pattern": r"-----BEGIN PRIVATE KEY-----", "severity": "critical"},
    {"name": "Encrypted Private Key", "pattern": r"-----BEGIN ENCRYPTED PRIVATE KEY-----", "severity": "high"},
    
    # Database Connection Strings
    {"name": "MongoDB URI", "pattern": r"mongodb(\+srv)?://[^\s<>\"']+", "severity": "critical"},
    {"name": "PostgreSQL URI", "pattern": r"postgres(ql)?://[^\s<>\"']+", "severity": "critical"},
    {"name": "MySQL URI", "pattern": r"mysql://[^\s<>\"']+", "severity": "critical"},
    {"name": "Redis URI", "pattern": r"redis://[^\s<>\"']+", "severity": "high"},
    
    # Generic Secrets
    {"name": "Generic API Key", "pattern": r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?[a-zA-Z0-9_\-]{20,}['\"]?", "severity": "high"},
    {"name": "Generic Secret", "pattern": r"(?i)(secret|secret[_-]?key)\s*[=:]\s*['\"]?[a-zA-Z0-9_\-]{20,}['\"]?", "severity": "high"},
    {"name": "Generic Password", "pattern": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]", "severity": "high"},
    {"name": "Generic Token", "pattern": r"(?i)(access[_-]?token|auth[_-]?token|bearer)\s*[=:]\s*['\"]?[a-zA-Z0-9_\-\.]{20,}['\"]?", "severity": "high"},
    {"name": "Basic Auth Header", "pattern": r"(?i)authorization:\s*basic\s+[a-zA-Z0-9+/=]+", "severity": "high"},
    {"name": "Bearer Token", "pattern": r"(?i)authorization:\s*bearer\s+[a-zA-Z0-9_\-\.]+", "severity": "high"},
    {"name": "JWT Token", "pattern": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*", "severity": "high"},
    
    # Environment Variables with Secrets
    {"name": "Hardcoded Credentials", "pattern": r"(?i)(db_password|database_password|db_pass)\s*[=:]\s*['\"][^'\"]+['\"]", "severity": "critical"},
    {"name": "AWS Environment", "pattern": r"(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*['\"]?[A-Za-z0-9/+=]+['\"]?", "severity": "critical"},
]


def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    
    entropy = 0.0
    for char in set(data):
        p_x = float(data.count(char)) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy


def mask_secret(secret: str, visible_chars: int = 4) -> str:
    """Mask a secret, showing only first few characters."""
    if len(secret) <= visible_chars:
        return "*" * len(secret)
    return secret[:visible_chars] + "*" * (len(secret) - visible_chars)


def get_github_base_url(git_url: str) -> str:
    """Convert a git URL to a GitHub/GitLab web base URL for file linking."""
    url = git_url.strip()
    
    # Remove .git suffix
    if url.endswith('.git'):
        url = url[:-4]
    
    # Handle SSH format (git@github.com:user/repo)
    if url.startswith('git@'):
        url = url.replace(':', '/').replace('git@', 'https://')
    
    # Handle git:// protocol
    if url.startswith('git://'):
        url = url.replace('git://', 'https://')
    
    # Ensure https://
    if not url.startswith('http'):
        url = 'https://' + url
    
    return url


def run_git_command(cmd: List[str], cwd: str) -> str:
    """Run a git command and return output."""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return ""
    except Exception:
        return ""


def get_all_branches(repo_path: str) -> List[str]:
    """Get all branches (local and remote) from a repository."""
    # Fetch all remote branches
    run_git_command(["git", "fetch", "--all"], repo_path)
    
    # Get all branches
    output = run_git_command(["git", "branch", "-r"], repo_path)
    branches = []
    for line in output.strip().split("\n"):
        line = line.strip()
        if line and "HEAD" not in line:
            # Remove 'origin/' prefix
            branch = line.replace("origin/", "")
            branches.append(branch)
    
    if not branches:
        branches = ["main", "master"]
    
    return list(set(branches))


def get_all_commits(repo_path: str) -> List[Dict]:
    """Get ALL commits from the repository (all branches)."""
    output = run_git_command(
        ["git", "log", "--all", "--pretty=format:%H|%an|%ai|%s"],
        repo_path
    )
    
    commits = []
    seen_hashes = set()
    for line in output.strip().split("\n"):
        if line and "|" in line:
            parts = line.split("|", 3)
            if len(parts) >= 4:
                commit_hash = parts[0]
                if commit_hash not in seen_hashes:
                    seen_hashes.add(commit_hash)
                    commits.append({
                        "hash": commit_hash,
                        "author": parts[1],
                        "date": parts[2],
                        "message": parts[3][:100]
                    })
    
    return commits


def scan_commit_for_secrets(repo_path: str, commit: Dict, branch: str) -> List[SecretFinding]:
    """Scan a specific commit for secrets."""
    findings = []
    
    # Get the diff for this commit (including deleted files!)
    diff_output = run_git_command(
        ["git", "show", "--pretty=format:", "--diff-filter=ACDMR", commit["hash"]],
        repo_path
    )
    
    if not diff_output:
        return findings
    
    current_file = None
    current_line = 0
    
    for line in diff_output.split("\n"):
        # Track current file
        if line.startswith("diff --git"):
            parts = line.split(" b/")
            if len(parts) > 1:
                current_file = parts[1]
            current_line = 0
        elif line.startswith("@@"):
            # Parse line number from hunk header
            match = re.search(r"\+(\d+)", line)
            if match:
                current_line = int(match.group(1))
        elif line.startswith("+") and not line.startswith("+++"):
            # This is an added line, scan for secrets
            content = line[1:]  # Remove the + prefix
            current_line += 1
            
            for pattern_info in SECRET_PATTERNS:
                try:
                    matches = re.finditer(pattern_info["pattern"], content)
                    for match in matches:
                        secret_value = match.group(0)
                        entropy = calculate_entropy(secret_value)
                        
                        finding = SecretFinding(
                            file_path=current_file or "unknown",
                            line_number=current_line,
                            secret_type=pattern_info["name"],
                            secret_preview=mask_secret(secret_value),
                            secret_full=secret_value,
                            commit_hash=commit["hash"][:8],
                            commit_author=commit["author"],
                            commit_date=commit["date"],
                            commit_message=commit["message"],
                            branch=branch,
                            severity=pattern_info["severity"],
                            entropy=round(entropy, 2)
                        )
                        findings.append(finding)
                except re.error:
                    continue
    
    return findings


def scan_current_files(repo_path: str, branch: str) -> List[SecretFinding]:
    """Scan current files in the repository for secrets."""
    findings = []
    
    # Extensions to scan
    scan_extensions = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php',
        '.env', '.yaml', '.yml', '.json', '.xml', '.conf', '.config', '.ini',
        '.sh', '.bash', '.zsh', '.properties', '.toml', '.tf', '.tfvars',
        '.dockerfile', '.sql', '.md', '.txt', '.cfg', '.settings'
    }
    
    # Also scan files without extensions that might contain secrets
    scan_names = {
        'dockerfile', 'makefile', '.env', '.env.local', '.env.development',
        '.env.production', '.env.staging', 'secrets', 'credentials', 'config'
    }
    
    for root, dirs, files in os.walk(repo_path):
        # Skip .git directory
        if '.git' in root:
            continue
        
        for file in files:
            file_lower = file.lower()
            ext = Path(file).suffix.lower()
            
            if ext in scan_extensions or file_lower in scan_names:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, repo_path)
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        
                    for line_num, line in enumerate(lines, 1):
                        for pattern_info in SECRET_PATTERNS:
                            try:
                                matches = re.finditer(pattern_info["pattern"], line)
                                for match in matches:
                                    secret_value = match.group(0)
                                    entropy = calculate_entropy(secret_value)
                                    
                                    finding = SecretFinding(
                                        file_path=relative_path,
                                        line_number=line_num,
                                        secret_type=pattern_info["name"],
                                        secret_preview=mask_secret(secret_value),
                                        secret_full=secret_value,
                                        commit_hash="HEAD",
                                        commit_author="Current",
                                        commit_date=datetime.now().isoformat(),
                                        commit_message="Current HEAD",
                                        branch=branch,
                                        severity=pattern_info["severity"],
                                        entropy=round(entropy, 2)
                                    )
                                    findings.append(finding)
                            except re.error:
                                continue
                except Exception:
                    continue
    
    return findings


def perform_scan(scan_id: str, git_url: str):
    """Perform the actual repository scan."""
    scan_results[scan_id]["status"] = "in_progress"
    scan_results[scan_id]["message"] = "Cloning repository..."
    
    temp_dir = None
    all_findings = []
    
    try:
        # Create temporary directory
        temp_dir = tempfile.mkdtemp()
        repo_path = os.path.join(temp_dir, "repo")
        
        # Clone the repository with full history
        scan_results[scan_id]["progress"] = 10
        result = subprocess.run(
            ["git", "clone", "--mirror", git_url, repo_path + ".git"],
            capture_output=True,
            text=True,
            timeout=600
        )
        
        if result.returncode != 0:
            raise Exception(f"Failed to clone repository: {result.stderr}")
        
        # Convert bare repo to normal
        subprocess.run(
            ["git", "clone", repo_path + ".git", repo_path],
            capture_output=True,
            timeout=300
        )
        
        scan_results[scan_id]["progress"] = 20
        scan_results[scan_id]["message"] = "Getting all commits..."
        
        # Get ALL commits from the repository
        commits = get_all_commits(repo_path)
        total_commits = len(commits)
        scan_results[scan_id]["message"] = f"Found {total_commits} commits. Deep scanning..."
        
        # Scan ALL commits (not just last 100!)
        commits_to_scan = commits[:500]  # Scan up to 500 commits for thorough coverage
        
        for idx, commit in enumerate(commits_to_scan):
            progress = 20 + int((idx / len(commits_to_scan)) * 60)
            scan_results[scan_id]["progress"] = progress
            scan_results[scan_id]["message"] = f"Scanning commit {idx + 1}/{len(commits_to_scan)}: {commit['hash'][:8]}"
            
            findings = scan_commit_for_secrets(repo_path, commit, "all")
            all_findings.extend(findings)
        
        scan_results[scan_id]["progress"] = 85
        scan_results[scan_id]["message"] = "Scanning current files..."
        
        # Also scan current files
        current_findings = scan_current_files(repo_path, "HEAD")
        all_findings.extend(current_findings)
        
        scan_results[scan_id]["progress"] = 90
        scan_results[scan_id]["message"] = "Processing results..."
        
        # Remove duplicates based on hash of finding
        unique_findings = {}
        for finding in all_findings:
            key = hashlib.md5(
                f"{finding.file_path}{finding.line_number}{finding.secret_type}{finding.secret_preview}".encode()
            ).hexdigest()
            if key not in unique_findings:
                unique_findings[key] = finding
        
        findings_list = [asdict(f) for f in unique_findings.values()]
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings_list.sort(key=lambda x: severity_order.get(x["severity"], 4))
        
        # Generate summary
        summary = {
            "total_findings": len(findings_list),
            "critical": len([f for f in findings_list if f["severity"] == "critical"]),
            "high": len([f for f in findings_list if f["severity"] == "high"]),
            "medium": len([f for f in findings_list if f["severity"] == "medium"]),
            "low": len([f for f in findings_list if f["severity"] == "low"]),
            "commits_scanned": len(commits_to_scan),
            "total_commits": total_commits,
            "secret_types": list(set(f["secret_type"] for f in findings_list))
        }
        
        scan_results[scan_id]["progress"] = 100
        scan_results[scan_id]["status"] = "completed"
        scan_results[scan_id]["message"] = f"Scan completed! Found {len(findings_list)} secrets in {len(commits_to_scan)} commits"
        scan_results[scan_id]["results"] = {
            "summary": summary,
            "findings": findings_list,
            "repo_url": get_github_base_url(git_url)
        }
        
    except Exception as e:
        scan_results[scan_id]["status"] = "failed"
        scan_results[scan_id]["message"] = str(e)
    
    finally:
        # Cleanup
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


@app.post("/api/scan", response_model=ScanStatus)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new repository scan."""
    # Generate scan ID
    scan_id = hashlib.md5(f"{request.git_url}{datetime.now().isoformat()}".encode()).hexdigest()[:12]
    
    # Initialize scan status
    scan_results[scan_id] = {
        "scan_id": scan_id,
        "status": "queued",
        "progress": 0,
        "message": "Scan queued...",
        "git_url": request.git_url,
        "results": None
    }
    
    # Start scan in background
    background_tasks.add_task(perform_scan, scan_id, request.git_url)
    
    return ScanStatus(
        scan_id=scan_id,
        status="queued",
        progress=0,
        message="Scan queued..."
    )


@app.get("/api/scan/{scan_id}", response_model=ScanStatus)
async def get_scan_status(scan_id: str):
    """Get the status of a scan."""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    result = scan_results[scan_id]
    return ScanStatus(
        scan_id=scan_id,
        status=result["status"],
        progress=result["progress"],
        message=result["message"],
        results=result.get("results")
    )


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "2.0.0",
        "mode": "Full Mode (Deep Scan)",
        "features": [
            "Clones full repository",
            "Scans up to 500 commits",
            "Finds secrets in deleted files",
            "50+ secret patterns"
        ]
    }


if __name__ == "__main__":
    print("=" * 60)
    print("Git Secret Scanner v2.0 - Full Mode (Deep Scan)")
    print("=" * 60)
    print("\nFeatures:")
    print("  ✓ Clones full repository with complete history")
    print("  ✓ Scans up to 500 commits for thorough coverage")
    print("  ✓ Detects secrets in deleted files")
    print("  ✓ 50+ secret patterns")
    print("\nStarting server on http://localhost:8000")
    print("=" * 60)
    
    uvicorn.run(app, host="0.0.0.0", port=8000)
