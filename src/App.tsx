import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { scanRepository, ScanResult, Finding } from './scanner'
import './App.css'

// Backend API URL - change this when deploying
const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000'

const severityColors: Record<string, string> = {
  critical: '#ff3366',
  high: '#ff9500',
  medium: '#ffd700',
  low: '#64748b'
}

const severityIcons: Record<string, string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '⚪'
}

// Generate GitHub link to specific file and line
const getRepoFileLink = (repoUrl: string, filePath: string, lineNumber: number, commitHash: string): string => {
  const ref = commitHash === 'HEAD' ? 'main' : commitHash
  return `${repoUrl}/blob/${ref}/${filePath}#L${lineNumber}`
}

type ScanMode = 'lite' | 'full'

interface BackendScanResult {
  summary: {
    total_findings: number
    critical: number
    high: number
    medium: number
    low: number
    commits_scanned: number
    total_commits?: number
    files_scanned?: number
    secret_types: string[]
  }
  findings: Finding[]
  repo_url: string
}

function App() {
  const [gitUrl, setGitUrl] = useState('')
  const [githubToken, setGithubToken] = useState('')
  const [showTokenInput, setShowTokenInput] = useState(false)
  const [scanMode, setScanMode] = useState<ScanMode>('full')
  const [scanning, setScanning] = useState(false)
  const [scanId, setScanId] = useState<string | null>(null)
  const [progress, setProgress] = useState(0)
  const [progressMessage, setProgressMessage] = useState('')
  const [results, setResults] = useState<ScanResult | BackendScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [filterSeverity, setFilterSeverity] = useState<string>('all')
  const [filterType, setFilterType] = useState<string>('all')
  const [revealedSecrets, setRevealedSecrets] = useState<Set<string>>(new Set())
  const [backendAvailable, setBackendAvailable] = useState<boolean | null>(null)

  // Check if backend is available
  useEffect(() => {
    const checkBackend = async () => {
      try {
        const response = await fetch(`${BACKEND_URL}/api/health`, { 
          method: 'GET',
          signal: AbortSignal.timeout(3000)
        })
        setBackendAvailable(response.ok)
      } catch {
        setBackendAvailable(false)
      }
    }
    checkBackend()
  }, [])

  // Poll backend for scan status
  const pollBackendStatus = useCallback(async (id: string) => {
    try {
      const response = await fetch(`${BACKEND_URL}/api/scan/${id}`)
      if (!response.ok) throw new Error('Failed to get scan status')
      
      const data = await response.json()
      setProgress(data.progress)
      setProgressMessage(data.message)
      
      if (data.status === 'completed') {
        setResults(data.results)
        setScanning(false)
      } else if (data.status === 'failed') {
        setError(data.message)
        setScanning(false)
      }
    } catch (err) {
      setError('Failed to get scan status from backend')
      setScanning(false)
    }
  }, [])

  useEffect(() => {
    if (scanning && scanId && scanMode === 'full') {
      const interval = setInterval(() => pollBackendStatus(scanId), 1500)
      return () => clearInterval(interval)
    }
  }, [scanning, scanId, scanMode, pollBackendStatus])

  const toggleSecretReveal = (key: string) => {
    setRevealedSecrets(prev => {
      const newSet = new Set(prev)
      if (newSet.has(key)) {
        newSet.delete(key)
      } else {
        newSet.add(key)
      }
      return newSet
    })
  }

  const startScan = async () => {
    if (!gitUrl.trim()) {
      setError('Please enter a Git URL')
      return
    }

    setError(null)
    setResults(null)
    setScanning(true)
    setProgress(0)
    setProgressMessage('Starting scan...')
    setRevealedSecrets(new Set())

    if (scanMode === 'full') {
      // Full Mode - Use Python backend
      try {
        const response = await fetch(`${BACKEND_URL}/api/scan`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ git_url: gitUrl })
        })

        if (!response.ok) {
          throw new Error('Failed to start scan. Is the backend running?')
        }

        const data = await response.json()
        setScanId(data.scan_id)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to connect to backend. Make sure it is running on ' + BACKEND_URL)
        setScanning(false)
      }
    } else {
      // Lite Mode - Browser-based scanning
      if (!gitUrl.includes('github.com')) {
        setError('Lite Mode only supports GitHub repositories')
        setScanning(false)
        return
      }

      try {
        const result = await scanRepository(
          gitUrl,
          githubToken || undefined,
          (message, prog) => {
            setProgressMessage(message)
            setProgress(prog)
          }
        )
        setResults(result)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Scan failed')
      } finally {
        setScanning(false)
      }
    }
  }

  const filteredFindings = results?.findings.filter((f: Finding) => {
    if (filterSeverity !== 'all' && f.severity !== filterSeverity) return false
    if (filterType !== 'all' && f.secret_type !== filterType) return false
    return true
  }) || []

  const uniqueTypes = [...new Set(results?.findings.map((f: Finding) => f.secret_type) || [])]

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <motion.div 
          className="logo"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
        >
          <div className="logo-icon">
            <svg viewBox="0 0 100 100" fill="none">
              <circle cx="50" cy="50" r="45" stroke="url(#logoGrad)" strokeWidth="4"/>
              <path d="M50 25 L50 45 M50 55 L50 75 M25 50 L45 50 M55 50 L75 50" stroke="url(#logoGrad)" strokeWidth="4" strokeLinecap="round"/>
              <circle cx="50" cy="50" r="8" fill="url(#logoGrad)"/>
              <defs>
                <linearGradient id="logoGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#00d4ff"/>
                  <stop offset="100%" stopColor="#00ff88"/>
                </linearGradient>
              </defs>
            </svg>
          </div>
          <div className="logo-text">
            <h1>Git Secret Scanner</h1>
            <p>Find exposed secrets in Git repositories</p>
          </div>
        </motion.div>
      </header>

      {/* Main Content */}
      <main className="main">
        {/* Scanner Input */}
        <motion.section 
          className="scanner-section"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
        >
          <div className="scanner-card">
            {/* Mode Selector */}
            <div className="mode-selector">
              <button 
                className={`mode-button ${scanMode === 'full' ? 'active' : ''}`}
                onClick={() => setScanMode('full')}
                disabled={scanning}
              >
                <span className="mode-icon">🔥</span>
                <span className="mode-label">Full Mode</span>
                <span className="mode-desc">Deep scan (500 commits, deleted files)</span>
                {backendAvailable === false && <span className="mode-warning">⚠️ Backend offline</span>}
              </button>
              <button 
                className={`mode-button ${scanMode === 'lite' ? 'active' : ''}`}
                onClick={() => setScanMode('lite')}
                disabled={scanning}
              >
                <span className="mode-icon">⚡</span>
                <span className="mode-label">Lite Mode</span>
                <span className="mode-desc">Browser-only (GitHub API, 20 commits)</span>
              </button>
            </div>

            <div className="input-group">
              <div className="input-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/>
                </svg>
              </div>
              <input
                type="url"
                placeholder={scanMode === 'full' 
                  ? "Enter any Git repository URL (GitHub, GitLab, etc.)" 
                  : "Enter GitHub repository URL"}
                value={gitUrl}
                onChange={(e) => setGitUrl(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && !scanning && startScan()}
                disabled={scanning}
              />
              <button 
                className="scan-button"
                onClick={startScan}
                disabled={scanning || (scanMode === 'full' && backendAvailable === false)}
              >
                {scanning ? (
                  <>
                    <span className="spinner"></span>
                    Scanning...
                  </>
                ) : (
                  <>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="11" cy="11" r="8"/>
                      <path d="m21 21-4.3-4.3"/>
                    </svg>
                    Scan Repository
                  </>
                )}
              </button>
            </div>

            {/* Token Input for Lite Mode */}
            {scanMode === 'lite' && (
              <div className="token-section">
                <button 
                  className="token-toggle"
                  onClick={() => setShowTokenInput(!showTokenInput)}
                >
                  🔑 {showTokenInput ? 'Hide' : 'Add'} GitHub Token (optional, increases rate limit)
                </button>
                
                <AnimatePresence>
                  {showTokenInput && (
                    <motion.div
                      className="token-input-wrapper"
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                    >
                      <input
                        type="password"
                        placeholder="GitHub Personal Access Token (ghp_...)"
                        value={githubToken}
                        onChange={(e) => setGithubToken(e.target.value)}
                        className="token-input"
                      />
                      <p className="token-hint">
                        Without a token: 60 requests/hour. With token: 5000 requests/hour.
                        <a href="https://github.com/settings/tokens" target="_blank" rel="noopener noreferrer"> Create token →</a>
                      </p>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            )}

            <div className="features">
              {scanMode === 'full' ? (
                <>
                  <div className="feature">
                    <span className="feature-icon">📚</span>
                    <span>500 Commits</span>
                  </div>
                  <div className="feature">
                    <span className="feature-icon">🗑️</span>
                    <span>Deleted Files</span>
                  </div>
                  <div className="feature">
                    <span className="feature-icon">🔐</span>
                    <span>50+ Patterns</span>
                  </div>
                  <div className="feature">
                    <span className="feature-icon">🌿</span>
                    <span>All Branches</span>
                  </div>
                </>
              ) : (
                <>
                  <div className="feature">
                    <span className="feature-icon">⚡</span>
                    <span>Fast Scan</span>
                  </div>
                  <div className="feature">
                    <span className="feature-icon">🌐</span>
                    <span>No Backend</span>
                  </div>
                  <div className="feature">
                    <span className="feature-icon">🔐</span>
                    <span>40+ Patterns</span>
                  </div>
                  <div className="feature">
                    <span className="feature-icon">📜</span>
                    <span>20 Commits</span>
                  </div>
                </>
              )}
            </div>
          </div>
        </motion.section>

        {/* Error Display */}
        <AnimatePresence>
          {error && (
            <motion.div 
              className="error-banner"
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
            >
              <svg viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>
              </svg>
              <span>{error}</span>
              <button onClick={() => setError(null)}>×</button>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Progress */}
        <AnimatePresence>
          {scanning && (
            <motion.section 
              className="progress-section"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
            >
              <div className="progress-card">
                <div className="progress-header">
                  <h3>
                    {scanMode === 'full' ? '🔥 Full Mode Scan' : '⚡ Lite Mode Scan'}
                  </h3>
                  <span className="progress-percent">{progress}%</span>
                </div>
                <div className="progress-bar">
                  <motion.div 
                    className="progress-fill"
                    initial={{ width: 0 }}
                    animate={{ width: `${progress}%` }}
                    transition={{ duration: 0.3 }}
                  />
                </div>
                <p className="progress-message">{progressMessage}</p>
              </div>
            </motion.section>
          )}
        </AnimatePresence>

        {/* Results */}
        <AnimatePresence>
          {results && (
            <motion.section 
              className="results-section"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
            >
              {/* Summary Cards */}
              <div className="summary-grid">
                <motion.div 
                  className="summary-card total"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.1 }}
                >
                  <div className="summary-icon">🔍</div>
                  <div className="summary-content">
                    <span className="summary-value">{results.summary.total_findings}</span>
                    <span className="summary-label">Total Findings</span>
                  </div>
                </motion.div>

                <motion.div 
                  className="summary-card critical"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.15 }}
                >
                  <div className="summary-icon">🔴</div>
                  <div className="summary-content">
                    <span className="summary-value">{results.summary.critical}</span>
                    <span className="summary-label">Critical</span>
                  </div>
                </motion.div>

                <motion.div 
                  className="summary-card high"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.2 }}
                >
                  <div className="summary-icon">🟠</div>
                  <div className="summary-content">
                    <span className="summary-value">{results.summary.high}</span>
                    <span className="summary-label">High</span>
                  </div>
                </motion.div>

                <motion.div 
                  className="summary-card medium"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.25 }}
                >
                  <div className="summary-icon">🟡</div>
                  <div className="summary-content">
                    <span className="summary-value">{results.summary.medium}</span>
                    <span className="summary-label">Medium</span>
                  </div>
                </motion.div>

                <motion.div 
                  className="summary-card commits"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.3 }}
                >
                  <div className="summary-icon">📚</div>
                  <div className="summary-content">
                    <span className="summary-value">{results.summary.commits_scanned}</span>
                    <span className="summary-label">Commits Scanned</span>
                  </div>
                </motion.div>
              </div>

              {/* Filters */}
              {results.findings.length > 0 && (
                <div className="filters">
                  <div className="filter-group">
                    <label>Severity:</label>
                    <select 
                      value={filterSeverity} 
                      onChange={(e) => setFilterSeverity(e.target.value)}
                    >
                      <option value="all">All Severities</option>
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                  </div>
                  <div className="filter-group">
                    <label>Type:</label>
                    <select 
                      value={filterType} 
                      onChange={(e) => setFilterType(e.target.value)}
                    >
                      <option value="all">All Types</option>
                      {uniqueTypes.map(type => (
                        <option key={type} value={type}>{type}</option>
                      ))}
                    </select>
                  </div>
                  <div className="filter-count">
                    Showing {filteredFindings.length} of {results.findings.length} findings
                  </div>
                </div>
              )}

              {/* Findings List */}
              <div className="findings-list">
                {filteredFindings.length === 0 ? (
                  <div className="no-findings">
                    <div className="no-findings-icon">✅</div>
                    <h3>No Secrets Found</h3>
                    <p>Great job! No exposed secrets were detected in this repository.</p>
                  </div>
                ) : (
                  filteredFindings.map((finding, index) => (
                    <motion.div 
                      key={`${finding.file_path}-${finding.line_number}-${index}`}
                      className="finding-card"
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: index * 0.03 }}
                    >
                      <div className="finding-header">
                        <div className="finding-severity" style={{ background: severityColors[finding.severity] }}>
                          {severityIcons[finding.severity]} {finding.severity.toUpperCase()}
                        </div>
                        <div className="finding-type">{finding.secret_type}</div>
                      </div>
                      
                      <div className="finding-details">
                        <div className="finding-file">
                          <a 
                            href={getRepoFileLink(results.repo_url, finding.file_path, finding.line_number, finding.commit_hash)}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="file-link"
                            title="Open in GitHub (line will be highlighted)"
                          >
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                              <polyline points="14,2 14,8 20,8"/>
                            </svg>
                            <code>{finding.file_path}</code>
                            <span className="line-number">Line {finding.line_number}</span>
                            <svg className="external-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
                              <polyline points="15 3 21 3 21 9"/>
                              <line x1="10" y1="14" x2="21" y2="3"/>
                            </svg>
                          </a>
                        </div>
                        
                        <div className="finding-secret">
                          <span className="secret-label">
                            Secret {revealedSecrets.has(`${finding.file_path}-${finding.line_number}-${index}`) ? '(revealed)' : '(masked)'}:
                          </span>
                          <code className={`secret-value ${revealedSecrets.has(`${finding.file_path}-${finding.line_number}-${index}`) ? 'revealed' : ''}`}>
                            {revealedSecrets.has(`${finding.file_path}-${finding.line_number}-${index}`) 
                              ? finding.secret_full 
                              : finding.secret_preview}
                          </code>
                          <button 
                            className="reveal-button"
                            onClick={() => toggleSecretReveal(`${finding.file_path}-${finding.line_number}-${index}`)}
                            title={revealedSecrets.has(`${finding.file_path}-${finding.line_number}-${index}`) ? 'Hide secret' : 'Reveal secret'}
                          >
                            {revealedSecrets.has(`${finding.file_path}-${finding.line_number}-${index}`) ? (
                              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
                                <line x1="1" y1="1" x2="23" y2="23"/>
                              </svg>
                            ) : (
                              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                                <circle cx="12" cy="12" r="3"/>
                              </svg>
                            )}
                          </button>
                        </div>
                        
                        <div className="finding-commit">
                          <div className="commit-info">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <circle cx="12" cy="12" r="4"/>
                              <line x1="1.05" y1="12" x2="7" y2="12"/>
                              <line x1="17.01" y1="12" x2="22.96" y2="12"/>
                            </svg>
                            <span className="commit-hash">{finding.commit_hash}</span>
                          </div>
                          <div className="commit-meta">
                            <span className="commit-author">{finding.commit_author}</span>
                            <span className="commit-message">{finding.commit_message}</span>
                          </div>
                        </div>
                        
                        <div className="finding-entropy">
                          Entropy: <span className={finding.entropy > 4 ? 'high-entropy' : ''}>{finding.entropy}</span>
                        </div>
                      </div>
                    </motion.div>
                  ))
                )}
              </div>
            </motion.section>
          )}
        </AnimatePresence>
      </main>

      {/* Footer */}
      <footer className="footer">
        <p>
          Git Secret Scanner — {scanMode === 'full' 
            ? 'Full Mode uses Python backend for deep scanning' 
            : 'Lite Mode runs entirely in your browser'}
        </p>
      </footer>
    </div>
  )
}

export default App
