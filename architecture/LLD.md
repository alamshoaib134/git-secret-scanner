# 🔧 Low-Level Design (LLD)

## Git Secret Scanner - Detailed Technical Design

---

## 1. Module Architecture

```mermaid
flowchart TB
    subgraph Frontend["Frontend Modules"]
        APP[App.tsx<br/>Main Component]
        UI[UI Components]
        SCANNER[scanner.ts<br/>Lite Mode]
    end

    subgraph Backend["Backend Modules"]
        MAIN[app.py<br/>Main Server]
        ENGINE[Scanner Engine]
        ROUTES[API Routes]
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
    
    Idle --> Scanning: Click "Scan"
    Scanning --> Polling: Full Mode
    Scanning --> Processing: Lite Mode
    
    Polling --> Polling: Every 2s
    Polling --> Completed: status=completed
    Polling --> Error: status=error
    
    Processing --> Completed: Scan done
    Processing --> Error: API error
    
    Completed --> Idle: New scan
    Error --> Idle: Retry

    note right of Scanning
        progress: 0-100%
        progressMessage: "..."
    end note
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
    APP[App.tsx]
    
    APP --> HEADER[Header]
    APP --> CARD[ScannerCard]
    APP --> PROGRESS[ProgressIndicator]
    APP --> RESULTS[ResultsPanel]
    APP --> FOOTER[Footer]
    
    HEADER --> LOGO[Logo]
    HEADER --> TITLE[Title]
    
    CARD --> MODE[ModeSelector]
    CARD --> INPUT[URLInput]
    CARD --> TOKEN[TokenInput]
    CARD --> BADGES[FeatureBadges]
    
    MODE --> FULL_BTN[FullModeButton]
    MODE --> LITE_BTN[LiteModeButton]
    
    RESULTS --> SUMMARY[SummaryCards]
    RESULTS --> FILTER[FilterBar]
    RESULTS --> LIST[FindingsList]
    
    LIST --> FINDING[FindingCard]
    FINDING --> SEVERITY[SeverityBadge]
    FINDING --> LINK[FileLink]
    FINDING --> SECRET[SecretDisplay]
    FINDING --> COMMIT[CommitInfo]
```

---

## 4. Secret Pattern Categories

```mermaid
mindmap
  root((Secret<br/>Patterns))
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
    START([scanRepository]) --> PARSE[parseGitHubUrl]
    PARSE --> BRANCHES[getBranches<br/>max 10]
    
    BRANCHES --> LOOP1{For each branch}
    LOOP1 --> TREE[getFileTree]
    TREE --> FILTER[Filter by extension<br/>.js, .py, .env, etc.]
    
    FILTER --> LOOP2{For each file<br/>max 100}
    LOOP2 --> CONTENT[getFileContent]
    CONTENT --> SCAN1[scanContent<br/>Pattern matching]
    SCAN1 --> LOOP2
    
    LOOP2 --> COMMITS[getCommits<br/>max 30]
    COMMITS --> LOOP3{For each commit<br/>max 20}
    LOOP3 --> DIFF[getCommitDiff]
    DIFF --> ADDED[Extract + lines]
    ADDED --> SCAN2[scanContent]
    SCAN2 --> LOOP3
    
    LOOP3 --> DEDUP[Deduplicate<br/>by hash]
    DEDUP --> RETURN([Return Results])
```

---

## 6. Backend Scan Flow

```mermaid
flowchart TD
    START([perform_scan]) --> TEMP[Create temp directory]
    TEMP --> CLONE[git clone --mirror]
    CLONE --> CONVERT[Convert to regular repo]
    CONVERT --> GETBRANCH[Get all branches]
    
    GETBRANCH --> LOOP1{For each branch}
    LOOP1 --> CHECKOUT[git checkout branch]
    CHECKOUT --> GETCOMMITS[Get commits<br/>max 500]
    
    GETCOMMITS --> LOOP2{For each commit}
    LOOP2 --> SHOW[git show --diff-filter=AM]
    SHOW --> EXTRACT[Extract added lines]
    
    EXTRACT --> LOOP3{For each pattern}
    LOOP3 --> MATCH[re.finditer]
    MATCH --> ENTROPY[Calculate entropy]
    ENTROPY --> FINDING[Create SecretFinding]
    FINDING --> LOOP3
    
    LOOP3 --> LOOP2
    LOOP2 --> FILES[Scan current files]
    FILES --> LOOP1
    
    LOOP1 --> DEDUP[Deduplicate findings]
    DEDUP --> SORT[Sort by severity]
    SORT --> UPDATE[Update scan_results]
    UPDATE --> CLEANUP[Cleanup temp dir]
    CLEANUP --> END([Done])
```

---

## 7. API Endpoints

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server

    rect rgb(50, 50, 50)
        Note over C,S: POST /api/scan
        C->>S: {"git_url": "https://github.com/user/repo"}
        S-->>C: {"scan_id": "uuid", "status": "scanning"}
    end

    rect rgb(50, 50, 50)
        Note over C,S: GET /api/scan/{scan_id} (polling)
        C->>S: Request status
        S-->>C: {"status": "scanning", "progress": 45}
    end

    rect rgb(50, 50, 50)
        Note over C,S: GET /api/scan/{scan_id} (completed)
        C->>S: Request status
        S-->>C: {"status": "completed", "findings": [...]}
    end
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
    INPUT[Input String] --> COUNT[Count char<br/>frequency]
    COUNT --> PROB[Calculate<br/>probability]
    PROB --> SHANNON[Shannon Formula<br/>H = -Σ p×log₂p]
    SHANNON --> OUTPUT[Entropy Score]
    
    subgraph Examples
        E1["password123<br/>→ 3.18 LOW"]
        E2["aK9$mP2@xL4!<br/>→ 4.58 HIGH"]
        E3["AKIAIOSFODNN<br/>→ 3.25 MED"]
    end
```

### Formula

```
H(X) = -Σ P(xᵢ) × log₂(P(xᵢ))

Where:
- H(X) = entropy of string X
- P(xᵢ) = probability of character xᵢ
- Higher entropy (>4.0) = more random = likely secret
```

---

## 9. File Extension Filter

```mermaid
graph TD
    subgraph Scanned["✅ Scanned Extensions"]
        CONFIG[".env, .json, .yaml, .yml<br/>.toml, .ini, .cfg, .conf"]
        CODE[".js, .jsx, .ts, .tsx<br/>.py, .rb, .php, .java<br/>.go, .rs, .sh"]
        DATA[".sql, .xml, .md, .txt<br/>.properties"]
    end

    subgraph Excluded["❌ Excluded"]
        BINARY[".png, .jpg, .gif<br/>.pdf, .zip, .exe"]
        DEPS["node_modules/<br/>venv/, vendor/"]
        LARGE["Files > 1MB"]
    end

    style Scanned fill:#00ff88,stroke:#fff,color:#000
    style Excluded fill:#ff4444,stroke:#fff,color:#fff
```

---

## 10. Error Handling

```mermaid
flowchart TD
    subgraph Frontend["Frontend Errors"]
        FE1[Invalid URL] -->|Regex check| FEH1[Show validation error]
        FE2[Network failure] -->|fetch catch| FEH2[Show retry button]
        FE3[Rate limited] -->|403 + header| FEH3[Suggest add token]
        FE4[Private repo] -->|404| FEH4[Show access error]
    end

    subgraph Backend["Backend Errors"]
        BE1[Clone failed] -->|CalledProcessError| BEH1[Set status=error]
        BE2[Invalid regex] -->|re.error| BEH2[Skip pattern]
        BE3[File read error] -->|IOError| BEH3[Skip file]
        BE4[Git timeout] -->|Timeout| BEH4[Skip operation]
    end
```

---

## 11. Finding Deduplication

```mermaid
flowchart LR
    FINDING[Finding] --> EXTRACT[Extract fields:<br/>file + line + type + preview]
    EXTRACT --> HASH[MD5 Hash]
    HASH --> CHECK{In Set?}
    CHECK -->|No| ADD[Add to Set<br/>Keep finding]
    CHECK -->|Yes| SKIP[Discard duplicate]
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
    subgraph Critical["🔴 Critical"]
        C1[AWS Keys]
        C2[Private Keys]
        C3[Database URIs]
    end

    subgraph High["🟠 High"]
        H1[API Tokens]
        H2[OAuth Secrets]
        H3[Webhook URLs]
    end

    subgraph Medium["🟡 Medium"]
        M1[Publishable Keys]
        M2[Client IDs]
        M3[Generic Secrets]
    end

    subgraph Low["🟢 Low"]
        L1[Test Tokens]
        L2[Example Keys]
        L3[Low Entropy]
    end
```

---

## 13. Performance Optimizations

```mermaid
flowchart TD
    subgraph Optimizations
        O1[Lazy Pattern Compile<br/>Once at load]
        O2[Early Termination<br/>Skip binary/large]
        O3[Parallel Processing<br/>ThreadPoolExecutor]
        O4[Hash Deduplication<br/>O(1) lookup]
        O5[Streaming Results<br/>Poll updates]
        O6[Git Mirror Clone<br/>Minimal data]
    end

    O1 --> FAST[Faster Scans]
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
        U1[Pattern Matching]
        U2[Entropy Calculation]
        U3[URL Parsing]
        U4[Secret Masking]
    end

    subgraph Integration["Integration Tests"]
        I1[Full Scan Flow]
        I2[API Endpoints]
        I3[Frontend-Backend]
    end

    subgraph E2E["End-to-End"]
        E1[Test Repo Scan]
        E2[UI Interactions]
        E3[Result Verification]
    end

    TEST_REPO[Test Repository<br/>github.com/alamshoaib134/MY-TOKENS]
    
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

## 16. Request/Response Flow

```mermaid
flowchart LR
    subgraph Request
        R1[POST /api/scan]
        R2[git_url: string]
    end

    subgraph Processing
        P1[Validate URL]
        P2[Generate scan_id]
        P3[Start background scan]
    end

    subgraph Response
        S1[scan_id: uuid]
        S2[status: scanning]
    end

    Request --> Processing --> Response
```
