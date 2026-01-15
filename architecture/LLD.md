# 🔧 Low-Level Design (LLD)

## Git Secret Scanner - Detailed Technical Design

---

## 1. Module Architecture

```mermaid
flowchart TB
    subgraph Frontend["Frontend Modules"]
        APP["App.tsx - Main Component"]
        UI["UI Components"]
        SCANNER["scanner.ts - Lite Mode"]
    end

    subgraph Backend["Backend Modules"]
        MAIN["app.py - Main Server"]
        ENGINE["Scanner Engine"]
        ROUTES["API Routes"]
    end

    APP --> UI
    APP --> SCANNER
    MAIN --> ENGINE
    MAIN --> ROUTES
```

---

## 2. Frontend State Management

```mermaid
stateDiagram-v2
    [*] --> Idle
    
    Idle --> Scanning: Click Scan
    Scanning --> Polling: Full Mode
    Scanning --> Processing: Lite Mode
    
    Polling --> Polling: Every 2s
    Polling --> Completed: Done
    Polling --> Error: Failed
    
    Processing --> Completed: Scan done
    Processing --> Error: API error
    
    Completed --> Idle: New scan
    Error --> Idle: Retry
```

### State Interface

```typescript
interface AppState {
  gitUrl: string;
  githubToken: string;
  mode: 'full' | 'lite';
  scanning: boolean;
  progress: number;
  progressMessage: string;
  results: ScanResults | null;
  error: string | null;
  filterSeverity: string;
  filterType: string;
  revealedSecrets: Set<string>;
}
```

---

## 3. Component Hierarchy

```mermaid
graph TD
    APP["App.tsx"]
    
    APP --> HEADER["Header"]
    APP --> CARD["ScannerCard"]
    APP --> PROGRESS["ProgressIndicator"]
    APP --> RESULTS["ResultsPanel"]
    APP --> FOOTER["Footer"]
    
    HEADER --> LOGO["Logo"]
    HEADER --> TITLE["Title"]
    
    CARD --> MODE["ModeSelector"]
    CARD --> INPUT["URLInput"]
    CARD --> TOKEN["TokenInput"]
    CARD --> BADGES["FeatureBadges"]
    
    MODE --> FULL_BTN["FullModeButton"]
    MODE --> LITE_BTN["LiteModeButton"]
    
    RESULTS --> SUMMARY["SummaryCards"]
    RESULTS --> FILTER["FilterBar"]
    RESULTS --> LIST["FindingsList"]
    
    LIST --> FINDING["FindingCard"]
    FINDING --> SEVERITY["SeverityBadge"]
    FINDING --> LINK["FileLink"]
    FINDING --> SECRET["SecretDisplay"]
    FINDING --> COMMIT["CommitInfo"]
```

---

## 4. Secret Pattern Categories

```mermaid
mindmap
  root((Secret Patterns))
    Cloud Providers
      AWS Access Key
      AWS Secret Key
      Azure Storage
      GCP API Key
    API Tokens
      GitHub Token
      Slack Token
      Stripe Key
      SendGrid
      Twilio
    Private Keys
      RSA Private
      OpenSSH
      DSA
      EC
      PGP
    Database
      MongoDB URI
      PostgreSQL
      MySQL
      Redis
    Generic
      Password
      API Key
      Secret
      Token
      Auth Header
```

### Pattern Structure

```typescript
interface SecretPattern {
  name: string;      // "AWS Access Key ID"
  pattern: RegExp;   // /AKIA[0-9A-Z]{16}/g
  severity: 'critical' | 'high' | 'medium' | 'low';
}
```

---

## 5. Lite Mode Scan Flow

```mermaid
flowchart TD
    START(["scanRepository"]) --> PARSE["parseGitHubUrl"]
    PARSE --> BRANCHES["getBranches - max 10"]
    
    BRANCHES --> LOOP1{"For each branch"}
    LOOP1 --> TREE["getFileTree"]
    TREE --> FILTER["Filter by extension"]
    
    FILTER --> LOOP2{"For each file - max 100"}
    LOOP2 --> CONTENT["getFileContent"]
    CONTENT --> SCAN1["scanContent"]
    SCAN1 --> LOOP2
    
    LOOP2 --> COMMITS["getCommits - max 30"]
    COMMITS --> LOOP3{"For each commit - max 20"}
    LOOP3 --> DIFF["getCommitDiff"]
    DIFF --> ADDED["Extract added lines"]
    ADDED --> SCAN2["scanContent"]
    SCAN2 --> LOOP3
    
    LOOP3 --> DEDUP["Deduplicate by hash"]
    DEDUP --> RETURN(["Return Results"])
```

---

## 6. Backend Scan Flow

```mermaid
flowchart TD
    START(["perform_scan"]) --> TEMP["Create temp directory"]
    TEMP --> CLONE["git clone --mirror"]
    CLONE --> CONVERT["Convert to regular repo"]
    CONVERT --> GETBRANCH["Get all branches"]
    
    GETBRANCH --> LOOP1{"For each branch"}
    LOOP1 --> CHECKOUT["git checkout branch"]
    CHECKOUT --> GETCOMMITS["Get commits - max 500"]
    
    GETCOMMITS --> LOOP2{"For each commit"}
    LOOP2 --> SHOW["git show diff"]
    SHOW --> EXTRACT["Extract added lines"]
    
    EXTRACT --> LOOP3{"For each pattern"}
    LOOP3 --> MATCH["regex finditer"]
    MATCH --> ENTROPY["Calculate entropy"]
    ENTROPY --> FINDING["Create SecretFinding"]
    FINDING --> LOOP3
    
    LOOP3 --> LOOP2
    LOOP2 --> FILES["Scan current files"]
    FILES --> LOOP1
    
    LOOP1 --> DEDUP["Deduplicate findings"]
    DEDUP --> SORT["Sort by severity"]
    SORT --> UPDATE["Update scan_results"]
    UPDATE --> CLEANUP["Cleanup temp dir"]
    CLEANUP --> END(["Done"])
```

---

## 7. API Endpoints

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server

    Note over C,S: POST /api/scan
    C->>S: git_url in request body
    S-->>C: scan_id and status

    Note over C,S: GET /api/scan/id - polling
    C->>S: Request status
    S-->>C: progress percentage

    Note over C,S: GET /api/scan/id - completed
    C->>S: Request status
    S-->>C: findings array
```

### Response Schema

```mermaid
erDiagram
    SCAN_RESPONSE {
        string status
        int progress
        string message
        object summary
        array findings
        string repo_url
    }
    
    SUMMARY {
        int total
        int critical
        int high
        int medium
        int low
        int commits_scanned
    }
    
    FINDING {
        string file_path
        int line_number
        string secret_type
        string secret_preview
        string secret_full
        string commit_hash
        string commit_author
        string commit_date
        string commit_message
        string branch
        string severity
        float entropy
    }
    
    SCAN_RESPONSE ||--|| SUMMARY : contains
    SCAN_RESPONSE ||--o{ FINDING : contains
```

---

## 8. Entropy Calculation

```mermaid
flowchart LR
    INPUT["Input String"] --> COUNT["Count char frequency"]
    COUNT --> PROB["Calculate probability"]
    PROB --> SHANNON["Shannon Formula"]
    SHANNON --> OUTPUT["Entropy Score"]
```

### Formula

```
H(X) = -Σ P(xᵢ) × log₂(P(xᵢ))

Where:
- H(X) = entropy of string X
- P(xᵢ) = probability of character xᵢ
- Higher entropy (>4.0) = more random = likely secret

Examples:
- "password123"  → entropy ≈ 3.18 (LOW)
- "aK9$mP2@xL4!" → entropy ≈ 4.58 (HIGH)
- "AKIAIOSFODNN" → entropy ≈ 3.25 (MEDIUM)
```

---

## 9. File Extension Filter

```mermaid
graph TD
    subgraph Scanned["Scanned Extensions"]
        CONFIG["Config: .env .json .yaml .yml .toml .ini"]
        CODE["Code: .js .ts .py .rb .php .java .go"]
        DATA["Data: .sql .xml .md .txt .properties"]
    end

    subgraph Excluded["Excluded"]
        BINARY["Binary: .png .jpg .gif .pdf .zip .exe"]
        DEPS["Deps: node_modules venv vendor"]
        LARGE["Large: Files over 1MB"]
    end
```

---

## 10. Error Handling

```mermaid
flowchart TD
    subgraph Frontend["Frontend Errors"]
        FE1["Invalid URL"] --> FEH1["Show validation error"]
        FE2["Network failure"] --> FEH2["Show retry button"]
        FE3["Rate limited"] --> FEH3["Suggest add token"]
        FE4["Private repo"] --> FEH4["Show access error"]
    end

    subgraph Backend["Backend Errors"]
        BE1["Clone failed"] --> BEH1["Set status error"]
        BE2["Invalid regex"] --> BEH2["Skip pattern"]
        BE3["File read error"] --> BEH3["Skip file"]
        BE4["Git timeout"] --> BEH4["Skip operation"]
    end
```

---

## 11. Finding Deduplication

```mermaid
flowchart LR
    FINDING["Finding"] --> EXTRACT["Extract fields"]
    EXTRACT --> HASH["MD5 Hash"]
    HASH --> CHECK{"In Set?"}
    CHECK -->|No| ADD["Add to Set - Keep"]
    CHECK -->|Yes| SKIP["Discard duplicate"]
```

---

## 12. Severity Classification

```mermaid
pie title Secret Severity Distribution
    "Critical" : 15
    "High" : 25
    "Medium" : 35
    "Low" : 25
```

```mermaid
graph LR
    subgraph Critical["Critical"]
        C1["AWS Keys"]
        C2["Private Keys"]
        C3["Database URIs"]
    end

    subgraph High["High"]
        H1["API Tokens"]
        H2["OAuth Secrets"]
        H3["Webhook URLs"]
    end

    subgraph Medium["Medium"]
        M1["Publishable Keys"]
        M2["Client IDs"]
        M3["Generic Secrets"]
    end

    subgraph Low["Low"]
        L1["Test Tokens"]
        L2["Example Keys"]
        L3["Low Entropy"]
    end
```

---

## 13. Performance Optimizations

```mermaid
flowchart TD
    subgraph Optimizations["Performance Optimizations"]
        O1["Lazy Pattern Compile"]
        O2["Early Termination"]
        O3["Parallel Processing"]
        O4["Hash Deduplication"]
        O5["Streaming Results"]
        O6["Git Mirror Clone"]
    end

    O1 --> FAST["Faster Scans"]
    O2 --> FAST
    O3 --> FAST
    O4 --> FAST
    O5 --> FAST
    O6 --> FAST
```

---

## 14. Testing Strategy

```mermaid
graph TD
    subgraph Unit["Unit Tests"]
        U1["Pattern Matching"]
        U2["Entropy Calculation"]
        U3["URL Parsing"]
        U4["Secret Masking"]
    end

    subgraph Integration["Integration Tests"]
        I1["Full Scan Flow"]
        I2["API Endpoints"]
        I3["Frontend-Backend"]
    end

    subgraph E2E["End-to-End"]
        E1["Test Repo Scan"]
        E2["UI Interactions"]
        E3["Result Verification"]
    end

    TEST_REPO["Test: github.com/alamshoaib134/MY-TOKENS"]
    
    Unit --> Integration --> E2E
    E2E --> TEST_REPO
```

---

## 15. Class Diagram

```mermaid
classDiagram
    class SecretFinding {
        +string file_path
        +int line_number
        +string secret_type
        +string secret_preview
        +string secret_full
        +string commit_hash
        +string commit_author
        +string commit_date
        +string commit_message
        +string branch
        +string severity
        +float entropy
    }

    class ScanResult {
        +string status
        +int progress
        +string message
        +Summary summary
        +SecretFinding[] findings
        +string repo_url
    }

    class Summary {
        +int total
        +int critical
        +int high
        +int medium
        +int low
        +int commits_scanned
        +int branches_scanned
    }

    class SecretPattern {
        +string name
        +RegExp pattern
        +string severity
    }

    ScanResult "1" --> "1" Summary
    ScanResult "1" --> "*" SecretFinding
    SecretFinding ..> SecretPattern : matched by
```

---

## 16. Request Response Flow

```mermaid
flowchart LR
    subgraph Request["Request"]
        R1["POST /api/scan"]
        R2["git_url string"]
    end

    subgraph Processing["Processing"]
        P1["Validate URL"]
        P2["Generate scan_id"]
        P3["Start background scan"]
    end

    subgraph Response["Response"]
        S1["scan_id uuid"]
        S2["status scanning"]
    end

    Request --> Processing --> Response
```
