# 🔧 Low-Level Design (LLD)

## Git Secret Scanner - Detailed Technical Design

---

## 1. Module Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           MODULE BREAKDOWN                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  FRONTEND MODULES                          BACKEND MODULES                  │
│  ─────────────────                         ───────────────                  │
│                                                                             │
│  ┌─────────────────┐                       ┌─────────────────┐             │
│  │    App.tsx      │                       │    app.py       │             │
│  │    (Main)       │                       │    (Main)       │             │
│  └────────┬────────┘                       └────────┬────────┘             │
│           │                                         │                       │
│  ┌────────┴────────┐                       ┌────────┴────────┐             │
│  │                 │                       │                 │             │
│  ▼                 ▼                       ▼                 ▼             │
│  ┌──────────┐ ┌──────────┐           ┌──────────┐ ┌──────────┐            │
│  │ UI       │ │ scanner  │           │ Scanner  │ │ API      │            │
│  │ Components│ │ .ts     │           │ Engine   │ │ Routes   │            │
│  └──────────┘ └──────────┘           └──────────┘ └──────────┘            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Frontend Components (App.tsx)

### 2.1 State Management

```typescript
// Core State Structure
interface AppState {
  // Input
  gitUrl: string;                    // Repository URL
  githubToken: string;               // Optional GitHub PAT
  mode: 'full' | 'lite';             // Scanning mode
  
  // Process
  scanning: boolean;                 // Scan in progress
  progress: number;                  // 0-100%
  progressMessage: string;           // Status text
  
  // Output
  results: ScanResults | null;       // Findings
  error: string | null;              // Error message
  
  // UI
  filterSeverity: string;            // Filter dropdown
  filterType: string;                // Type filter
  revealedSecrets: Set<string>;      // Revealed secret IDs
}
```

### 2.2 Component Hierarchy

```
App.tsx
├── Header
│   ├── Logo
│   └── Title
│
├── ScannerCard
│   ├── ModeSelector
│   │   ├── FullModeButton (active state)
│   │   └── LiteModeButton (active state)
│   │
│   ├── URLInput
│   │   ├── GitHubIcon
│   │   ├── TextInput
│   │   └── ScanButton
│   │
│   ├── TokenInput (Lite mode only)
│   │   └── CollapsibleInput
│   │
│   └── FeatureBadges
│       ├── CommitCount
│       ├── DeletedFiles (Full only)
│       ├── PatternCount
│       └── BranchInfo
│
├── ProgressIndicator (during scan)
│   ├── ProgressBar
│   └── StatusMessage
│
├── ResultsPanel (after scan)
│   ├── SummaryCards
│   │   ├── TotalFindings
│   │   ├── CriticalCount
│   │   ├── HighCount
│   │   ├── MediumCount
│   │   └── CommitsScanned
│   │
│   ├── FilterBar
│   │   ├── SeverityDropdown
│   │   ├── TypeDropdown
│   │   └── ResultCount
│   │
│   └── FindingsList
│       └── FindingCard (repeated)
│           ├── SeverityBadge
│           ├── TypeLabel
│           ├── FileLink (→ GitHub)
│           ├── SecretDisplay
│           │   ├── MaskedValue
│           │   └── RevealToggle
│           ├── CommitInfo
│           └── EntropyScore
│
└── Footer
```

### 2.3 Key Functions

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ FRONTEND FUNCTIONS                                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│ handleScan()                                                                │
│ ├── Validates URL                                                           │
│ ├── If mode === 'full'                                                      │
│ │   ├── POST /api/scan { git_url }                                         │
│ │   ├── Poll GET /api/scan/{id} every 2s                                   │
│ │   └── Update progress & results                                           │
│ └── If mode === 'lite'                                                      │
│     ├── Call scanRepository() from scanner.ts                              │
│     └── Handle progress callbacks                                           │
│                                                                             │
│ toggleSecretReveal(findingId: string)                                       │
│ ├── Add/remove from revealedSecrets Set                                     │
│ └── Re-render affected FindingCard                                          │
│                                                                             │
│ getRepoFileLink(repoUrl, filePath, lineNumber, commitHash)                  │
│ ├── Parse GitHub/GitLab/Bitbucket URL                                       │
│ ├── Build blob URL with commit ref                                          │
│ └── Return URL with #L{lineNumber} anchor                                   │
│                                                                             │
│ filterFindings(findings, severity, type)                                    │
│ ├── Filter by severity if not "All"                                         │
│ ├── Filter by type if not "All"                                             │
│ └── Return filtered array                                                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Lite Mode Scanner (scanner.ts)

### 3.1 Module Structure

```
scanner.ts
│
├── Constants
│   └── SECRET_PATTERNS[]           // 40+ regex patterns
│
├── Types
│   ├── SecretFinding
│   ├── ScanResults
│   └── ProgressCallback
│
├── Utility Functions
│   ├── parseGitHubUrl()            // Extract owner/repo
│   ├── calculateEntropy()          // Shannon entropy
│   └── maskSecret()                // XXXX**** format
│
├── GitHub API Functions
│   ├── fetchGitHub()               // Rate-limit aware fetch
│   ├── getBranches()               // GET /branches
│   ├── getFileTree()               // GET /git/trees
│   ├── getFileContent()            // GET /git/blobs
│   ├── getCommits()                // GET /commits
│   └── getCommitDiff()             // GET /commits/{sha}
│
├── Scanning Functions
│   ├── scanContent()               // Pattern matching
│   └── scanRepository()            // Main orchestrator
│
└── Exports
    └── { scanRepository, SECRET_PATTERNS }
```

### 3.2 Secret Pattern Structure

```typescript
interface SecretPattern {
  name: string;           // e.g., "AWS Access Key ID"
  pattern: RegExp;        // e.g., /AKIA[0-9A-Z]{16}/g
  severity: Severity;     // "critical" | "high" | "medium" | "low"
}

// Pattern Categories
PATTERNS = {
  CLOUD_PROVIDERS: [
    { name: "AWS Access Key ID", pattern: /AKIA[0-9A-Z]{16}/g, severity: "critical" },
    { name: "AWS Secret Key", pattern: /(?:aws)?_?secret_?(?:access)?_?key.{0,20}['\"][0-9a-zA-Z\/+]{40}['\"]/gi, severity: "critical" },
    { name: "Azure Storage Key", pattern: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+/gi, severity: "critical" },
    { name: "GCP API Key", pattern: /AIza[0-9A-Za-z\-_]{35}/g, severity: "high" },
  ],
  
  API_TOKENS: [
    { name: "GitHub Token", pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/g, severity: "critical" },
    { name: "Slack Token", pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g, severity: "high" },
    { name: "Stripe Key", pattern: /sk_live_[0-9a-zA-Z]{24,}/g, severity: "critical" },
    // ... more patterns
  ],
  
  PRIVATE_KEYS: [
    { name: "RSA Private Key", pattern: /-----BEGIN RSA PRIVATE KEY-----/g, severity: "critical" },
    { name: "OpenSSH Private Key", pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/g, severity: "critical" },
    // ... more patterns
  ],
  
  GENERIC: [
    { name: "Password Assignment", pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]/gi, severity: "high" },
    { name: "API Key Generic", pattern: /api[_-]?key\s*[:=]\s*['"][^'"]{16,}['"]/gi, severity: "medium" },
    // ... more patterns
  ]
}
```

### 3.3 Scan Flow Diagram

```
scanRepository(gitUrl, token, onProgress)
│
├─1─► parseGitHubUrl(gitUrl)
│     └── Returns { owner: "user", repo: "repo" }
│
├─2─► getBranches(owner, repo, token)
│     └── Returns ["main", "develop", ...]  (max 10)
│
├─3─► FOR EACH branch:
│     │
│     ├─3a─► getFileTree(owner, repo, branch, token)
│     │      └── Returns [{ path, sha, type }, ...]
│     │
│     ├─3b─► FILTER files by extension
│     │      └── Keep: .js, .ts, .py, .env, .json, .yml, etc.
│     │
│     └─3c─► FOR EACH file (max 100):
│            │
│            ├── getFileContent(owner, repo, sha, token)
│            │   └── Returns decoded file content
│            │
│            └── scanContent(content, path, ...)
│                └── Returns [Finding, Finding, ...]
│
├─4─► getCommits(owner, repo, "main", token, perPage=30)
│     └── Returns [{ sha, author, date, message }, ...]
│
├─5─► FOR EACH commit (max 20):
│     │
│     ├── getCommitDiff(owner, repo, sha, token)
│     │   └── Returns { files: [{ patch, filename }, ...] }
│     │
│     └── Parse patch for added lines (+)
│         └── scanContent(addedLines, ...)
│
├─6─► Deduplicate findings by hash
│     └── Hash = MD5(file + line + secret_type + preview)
│
└─7─► Return {
        summary: { total, critical, high, medium, low, commits },
        findings: [...],
        repo_url: gitUrl
      }
```

---

## 4. Backend Design (app.py)

### 4.1 Data Structures

```python
@dataclass
class SecretFinding:
    file_path: str          # "src/config.py"
    line_number: int        # 42
    secret_type: str        # "AWS Access Key ID"
    secret_preview: str     # "AKIA****"
    secret_full: str        # "AKIAIOSFODNN7EXAMPLE"
    commit_hash: str        # "abc123def"
    commit_author: str      # "John Doe"
    commit_date: str        # "2024-01-15"
    commit_message: str     # "Add config"
    branch: str             # "main"
    severity: str           # "critical"
    entropy: float          # 4.52

# In-memory storage
scan_results: Dict[str, Dict] = {
    "scan_id_123": {
        "status": "completed",      # "scanning" | "completed" | "error"
        "progress": 100,
        "message": "Scan complete",
        "summary": {...},
        "findings": [SecretFinding, ...],
        "repo_url": "https://..."
    }
}
```

### 4.2 API Endpoints Detail

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ POST /api/scan                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│ Request:                                                                    │
│ {                                                                           │
│   "git_url": "https://github.com/user/repo"                                │
│ }                                                                           │
│                                                                             │
│ Response:                                                                   │
│ {                                                                           │
│   "scan_id": "uuid-v4",                                                    │
│   "status": "scanning",                                                    │
│   "message": "Scan started"                                                │
│ }                                                                           │
│                                                                             │
│ Side Effect:                                                                │
│ └── Spawns background thread: perform_scan(scan_id, git_url)               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ GET /api/scan/{scan_id}                                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│ Response (in progress):                                                     │
│ {                                                                           │
│   "status": "scanning",                                                    │
│   "progress": 45,                                                          │
│   "message": "Scanning branch: develop (2/3)"                              │
│ }                                                                           │
│                                                                             │
│ Response (completed):                                                       │
│ {                                                                           │
│   "status": "completed",                                                   │
│   "progress": 100,                                                         │
│   "summary": {                                                             │
│     "total": 5,                                                            │
│     "critical": 1,                                                         │
│     "high": 2,                                                             │
│     "medium": 2,                                                           │
│     "low": 0,                                                              │
│     "commits_scanned": 150,                                                │
│     "branches_scanned": 3                                                  │
│   },                                                                       │
│   "findings": [                                                            │
│     {                                                                      │
│       "file_path": "config/secrets.py",                                   │
│       "line_number": 15,                                                   │
│       "secret_type": "AWS Access Key ID",                                 │
│       "secret_preview": "AKIA****************",                           │
│       "secret_full": "AKIAIOSFODNN7EXAMPLE",                              │
│       "commit_hash": "abc123",                                            │
│       "commit_author": "dev@example.com",                                 │
│       "commit_date": "2024-01-10",                                        │
│       "commit_message": "Initial commit",                                 │
│       "branch": "main",                                                    │
│       "severity": "critical",                                              │
│       "entropy": 4.52                                                      │
│     }                                                                      │
│   ],                                                                       │
│   "repo_url": "https://github.com/user/repo"                              │
│ }                                                                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.3 Scanning Algorithm

```
perform_scan(scan_id, git_url)
│
├─1─► Create temp directory
│     └── tempfile.mkdtemp()
│
├─2─► Clone repository (mirror mode)
│     └── git clone --mirror {git_url} {temp_dir}
│
├─3─► Convert to regular repo
│     └── git config --bool core.bare false
│
├─4─► Get all branches
│     └── git branch -r → ["origin/main", "origin/develop", ...]
│
├─5─► FOR EACH branch:
│     │
│     ├─5a─► Checkout branch
│     │      └── git checkout {branch}
│     │
│     ├─5b─► Get all commits (max 500)
│     │      └── git log --pretty=format:"%H|%an|%ai|%s" --all
│     │
│     ├─5c─► FOR EACH commit:
│     │      │
│     │      ├── Get commit diff
│     │      │   └── git show --pretty=format: --diff-filter=AM {hash}
│     │      │
│     │      ├── Extract added lines (lines starting with +)
│     │      │
│     │      └── FOR EACH pattern in SECRET_PATTERNS:
│     │          │
│     │          ├── re.finditer(pattern, content)
│     │          │
│     │          └── FOR EACH match:
│     │              ├── Calculate entropy
│     │              ├── Create SecretFinding
│     │              └── Add to findings list
│     │
│     └─5d─► Scan current files on branch
│            │
│            └── FOR EACH file (walk directory):
│                │
│                ├── Skip binary files
│                ├── Skip files > 1MB
│                │
│                └── FOR EACH pattern:
│                    └── Same as commit scanning
│
├─6─► Deduplicate findings
│     └── Hash = MD5(file + line + type + preview)
│
├─7─► Sort by severity
│     └── critical > high > medium > low
│
├─8─► Update scan_results[scan_id]
│     └── status = "completed", findings = [...]
│
└─9─► Cleanup
      └── shutil.rmtree(temp_dir)
```

### 4.4 Entropy Calculation

```
calculate_entropy(data: str) -> float
│
├── Count character frequency
│   └── freq = Counter(data)
│
├── Calculate probability for each char
│   └── p = count / len(data)
│
├── Apply Shannon entropy formula
│   └── H = -Σ(p * log2(p))
│
└── Return H
    └── Higher entropy (>4.0) = more random = likely a secret
    
Example:
  "password123"  → entropy ≈ 3.18 (low - dictionary word)
  "aK9$mP2@xL4!" → entropy ≈ 4.58 (high - random)
  "AKIAIOSFODNN" → entropy ≈ 3.25 (medium - pattern-based)
```

---

## 5. File Extensions Scanned

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ SCANNABLE FILE EXTENSIONS                                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│ Configuration:                                                              │
│ ├── .env, .env.local, .env.production                                      │
│ ├── .json, .yaml, .yml                                                     │
│ ├── .toml, .ini, .cfg                                                      │
│ └── .conf, .config                                                         │
│                                                                             │
│ Source Code:                                                                │
│ ├── .js, .jsx, .ts, .tsx                                                   │
│ ├── .py, .rb, .php                                                         │
│ ├── .java, .kt, .scala                                                     │
│ ├── .go, .rs, .c, .cpp                                                     │
│ └── .sh, .bash, .zsh                                                       │
│                                                                             │
│ Data/Docs:                                                                  │
│ ├── .sql, .xml                                                             │
│ ├── .md, .txt                                                              │
│ └── .properties                                                            │
│                                                                             │
│ Excluded:                                                                   │
│ ├── Binary: .png, .jpg, .gif, .pdf, .zip, .exe                             │
│ ├── Dependencies: node_modules/, venv/, vendor/                            │
│ └── Large files: > 1MB                                                     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Error Handling

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ ERROR HANDLING MATRIX                                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│ Frontend Errors:                                                            │
│ ┌────────────────────┬────────────────────┬─────────────────────────────┐  │
│ │ Error Type         │ Detection          │ User Feedback               │  │
│ ├────────────────────┼────────────────────┼─────────────────────────────┤  │
│ │ Invalid URL        │ Regex validation   │ "Please enter valid Git URL"│  │
│ │ Network failure    │ fetch() catch      │ "Network error. Retry?"     │  │
│ │ Rate limited       │ 403 + header check │ "Rate limited. Add token?"  │  │
│ │ Private repo       │ 404 response       │ "Repository not accessible" │  │
│ │ Scan timeout       │ 5 min timeout      │ "Scan timed out"            │  │
│ └────────────────────┴────────────────────┴─────────────────────────────┘  │
│                                                                             │
│ Backend Errors:                                                             │
│ ┌────────────────────┬────────────────────┬─────────────────────────────┐  │
│ │ Error Type         │ Handling           │ Recovery                    │  │
│ ├────────────────────┼────────────────────┼─────────────────────────────┤  │
│ │ Clone failed       │ CalledProcessError │ Set status="error", cleanup │  │
│ │ Invalid regex      │ re.error           │ Skip pattern, continue      │  │
│ │ File read error    │ IOError            │ Skip file, continue         │  │
│ │ Git command fail   │ Timeout/Exception  │ Skip operation, continue    │  │
│ │ Memory overflow    │ MemoryError        │ Limit findings, return      │  │
│ └────────────────────┴────────────────────┴─────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Performance Optimizations

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ PERFORMANCE OPTIMIZATIONS                                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│ 1. Lazy Pattern Compilation                                                 │
│    └── Compile regex patterns once at module load                          │
│                                                                             │
│ 2. Early Termination                                                        │
│    ├── Skip binary files (check magic bytes)                               │
│    ├── Skip files > 1MB                                                    │
│    └── Limit findings to 1000 per scan                                     │
│                                                                             │
│ 3. Parallel Processing (Future)                                            │
│    └── ThreadPoolExecutor for file scanning                                │
│                                                                             │
│ 4. Deduplication                                                            │
│    └── Hash-based set to avoid duplicate findings                          │
│                                                                             │
│ 5. Streaming Results                                                        │
│    └── Poll-based updates instead of waiting for full scan                 │
│                                                                             │
│ 6. Git Optimizations                                                        │
│    ├── --mirror clone (minimal data)                                       │
│    ├── --depth for shallow history (optional)                              │
│    └── Single git log command for all commits                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Testing Strategy

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ TEST CATEGORIES                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│ Unit Tests:                                                                 │
│ ├── Pattern matching accuracy (test each regex)                            │
│ ├── Entropy calculation correctness                                         │
│ ├── URL parsing (various Git URL formats)                                  │
│ └── Secret masking output                                                  │
│                                                                             │
│ Integration Tests:                                                          │
│ ├── Full scan of test repository                                           │
│ ├── API endpoint responses                                                 │
│ └── Frontend-backend communication                                         │
│                                                                             │
│ Test Repository:                                                            │
│ └── https://github.com/alamshoaib134/MY-TOKENS                             │
│     ├── Contains intentional test secrets                                  │
│     ├── Multiple file types                                                │
│     └── Commit history with secrets                                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```
