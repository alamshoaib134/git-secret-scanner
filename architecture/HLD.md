# 🏗️ High-Level Design (HLD)

## Git Secret Scanner - System Architecture

---

## 1. System Overview

```mermaid
flowchart TB
    subgraph UI["🖥️ User Interface (React + TypeScript)"]
        URL[URL Input]
        MODE[Mode Toggle<br/>Full / Lite]
        RESULTS[Results Dashboard]
    end

    subgraph FULL["🔥 FULL MODE (Python Backend)"]
        CLONE[Clone Repository]
        BRANCHES[Scan All Branches]
        COMMITS[500 Commit History]
        DELETED[Deleted File Detection]
        PATTERNS1[50+ Secret Patterns]
        API[FastAPI Server<br/>Port 8000]
    end

    subgraph LITE["⚡ LITE MODE (Browser Only)"]
        GHAPI[GitHub REST API]
        TREES[Fetch File Trees]
        DIFFS[20 Commit Diffs]
        PATTERNS2[40+ Secret Patterns]
        SCANNER[scanner.ts<br/>Client-side JS]
    end

    UI --> FULL
    UI --> LITE
    FULL --> API
    LITE --> SCANNER
```

---

## 2. Architecture Components

### 2.1 Frontend Layer

```mermaid
graph LR
    subgraph Frontend["Frontend Layer"]
        APP[App.tsx<br/>UI Logic & State]
        CSS[App.css<br/>Cyberpunk Theme]
        SCAN[scanner.ts<br/>Lite Mode Logic]
    end

    subgraph Tech["Technologies"]
        REACT[React 18]
        TS[TypeScript]
        VITE[Vite]
        MOTION[Framer Motion]
    end

    APP --> REACT
    APP --> TS
    CSS --> VITE
    SCAN --> TS
```

### 2.2 Backend Layer

```mermaid
graph TB
    subgraph Backend["Backend Layer - FastAPI Server"]
        E1[POST /api/scan<br/>Start repository scan]
        E2[GET /api/scan/id<br/>Get scan status & results]
        E3[GET /api/health<br/>Health check]
    end

    subgraph Tech["Technologies"]
        PY[Python 3.11]
        FAST[FastAPI]
        UV[Uvicorn]
        GIT[Git CLI]
    end

    E1 --> PY
    E2 --> FAST
    E3 --> UV
```

---

## 3. Data Flow Diagrams

### 3.1 Full Mode Flow

```mermaid
sequenceDiagram
    participant U as User
    participant F as Frontend<br/>(React)
    participant B as Backend<br/>(FastAPI)
    participant G as Git Server<br/>(GitHub)

    U->>F: Enter Repository URL
    F->>B: POST /api/scan {git_url}
    B-->>F: {scan_id, status: "scanning"}
    
    B->>G: git clone --mirror
    G-->>B: Repository data
    
    loop Every 2 seconds
        F->>B: GET /api/scan/{id}
        B-->>F: {progress, message}
    end
    
    Note over B: Scan commits<br/>Pattern matching<br/>Entropy calculation
    
    B-->>F: {status: "completed", findings}
    F->>U: Display Results
```

### 3.2 Lite Mode Flow

```mermaid
sequenceDiagram
    participant U as User
    participant F as Frontend<br/>(React + scanner.ts)
    participant G as GitHub API

    U->>F: Enter GitHub URL
    
    F->>G: GET /repos/{owner}/{repo}/branches
    G-->>F: Branch list
    
    F->>G: GET /git/trees/{branch}?recursive=1
    G-->>F: File tree
    
    loop For each file (max 100)
        F->>G: GET /git/blobs/{sha}
        G-->>F: File content
        Note over F: Pattern matching<br/>Entropy calculation
    end
    
    F->>G: GET /commits?sha={branch}
    G-->>F: Commit list
    
    loop For each commit (max 20)
        F->>G: GET /commits/{sha}
        G-->>F: Commit diff/patch
        Note over F: Scan added lines
    end
    
    F->>U: Display Results
```

---

## 4. Deployment Architecture

```mermaid
flowchart TB
    subgraph Internet["🌐 Internet"]
        USERS[Users]
    end

    subgraph Vercel["Vercel (Frontend Host)"]
        REACT_APP[React App<br/>Static Files]
        ENV1[VITE_BACKEND_URL]
    end

    subgraph Railway["Railway (Backend Host)"]
        FASTAPI[FastAPI<br/>Python Backend]
        ENV2[PORT auto-set]
    end

    USERS -->|HTTPS| Vercel
    USERS -->|HTTPS| Railway
    Vercel -->|API Calls| Railway

    style Vercel fill:#000,stroke:#00d4ff
    style Railway fill:#000,stroke:#00ff88
```

---

## 5. Security Architecture

```mermaid
flowchart TB
    subgraph L1["Layer 1: Input Validation"]
        V1[URL Format Validation]
        V2[Public Repo Check]
        V3[Rate Limiting]
    end

    subgraph L2["Layer 2: Data Processing"]
        P1[Temp Directory<br/>Auto-cleanup]
        P2[In-memory Storage<br/>No persistence]
        P3[Subprocess Sandboxing]
    end

    subgraph L3["Layer 3: Output Protection"]
        O1[Secret Masking<br/>AKIA**** format]
        O2[User-controlled Reveal]
        O3[CORS Configuration]
    end

    L1 --> L2 --> L3
```

---

## 6. Technology Stack

```mermaid
mindmap
  root((Git Secret<br/>Scanner))
    Frontend
      React 18
      TypeScript
      Vite
      Framer Motion
    Backend
      Python 3.11
      FastAPI
      Uvicorn
      Git CLI
    Deployment
      Vercel
      Railway
    Security
      50+ Patterns
      Entropy Detection
      Secret Masking
```

---

## 7. Component Interaction

```mermaid
graph TB
    subgraph Client["Client Browser"]
        UI[React UI]
        SCANNER[scanner.ts]
    end

    subgraph Server["Backend Server"]
        API[FastAPI]
        ENGINE[Scan Engine]
        PATTERNS[Pattern Matcher]
    end

    subgraph External["External Services"]
        GITHUB[GitHub API]
        GITLAB[GitLab]
        BITBUCKET[Bitbucket]
    end

    UI -->|Full Mode| API
    UI -->|Lite Mode| SCANNER
    SCANNER --> GITHUB
    API --> ENGINE
    ENGINE --> PATTERNS
    ENGINE -->|git clone| GITHUB
    ENGINE -->|git clone| GITLAB
    ENGINE -->|git clone| BITBUCKET
```

---

## 8. Scalability Considerations

```mermaid
flowchart LR
    subgraph Current["Current (MVP)"]
        S1[Single Instance]
        M1[In-memory Storage]
        SYNC[Synchronous]
    end

    subgraph Future["Future Scaling"]
        W1[Worker 1]
        W2[Worker 2]
        W3[Worker N]
        REDIS[(Redis Queue)]
        PG[(PostgreSQL)]
    end

    Current -->|Scale| Future
    W1 & W2 & W3 --> REDIS
    REDIS --> PG
```

---

## 9. Mode Comparison

```mermaid
graph LR
    subgraph Full["🔥 Full Mode"]
        F1[500 Commits]
        F2[Deleted Files ✅]
        F3[All Branches]
        F4[Any Git URL]
        F5[Backend Required]
    end

    subgraph Lite["⚡ Lite Mode"]
        L1[20 Commits]
        L2[Deleted Files ❌]
        L3[Default Branch]
        L4[GitHub Only]
        L5[No Backend]
    end

    style Full fill:#ff6b35,stroke:#fff
    style Lite fill:#00d4ff,stroke:#fff
```
