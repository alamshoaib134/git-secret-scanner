import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import './App.css'

interface Finding {
  file_path: string
  line_number: number
  secret_type: string
  secret_preview: string
  secret_full: string
  commit_hash: string
  commit_author: string
  commit_date: string
  commit_message: string
  branch: string
  severity: string
  entropy: number
}

interface ScanResults {
  summary: {
    total_findings: number
    critical: number
    high: number
    medium: number
    low: number
    branches_scanned: number
    secret_types: string[]
  }
  findings: Finding[]
  repo_url: string
}

interface ScanStatus {
  scan_id: string
  status: string
  progress: number
  message: string
  results: ScanResults | null
}

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

// Generate GitHub/GitLab link to specific file and line
const getRepoFileLink = (repoUrl: string, filePath: string, lineNumber: number, commitHash: string): string => {
  // Use commit hash for historical, or default branch for HEAD
  const ref = commitHash === 'HEAD' ? 'main' : commitHash
  // GitHub/GitLab URL format: https://github.com/user/repo/blob/{ref}/{path}#L{line}
  return `${repoUrl}/blob/${ref}/${filePath}#L${lineNumber}`
}

function App() {
  const [gitUrl, setGitUrl] = useState('')
  const [scanning, setScanning] = useState(false)
  const [scanId, setScanId] = useState<string | null>(null)
  const [status, setStatus] = useState<ScanStatus | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [filterSeverity, setFilterSeverity] = useState<string>('all')
  const [filterType, setFilterType] = useState<string>('all')
  const [revealedSecrets, setRevealedSecrets] = useState<Set<string>>(new Set())

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

  const pollStatus = useCallback(async (id: string) => {
    try {
      const response = await fetch(`/api/scan/${id}`)
      if (!response.ok) throw new Error('Failed to get scan status')
      
      const data: ScanStatus = await response.json()
      setStatus(data)
      
      if (data.status === 'completed' || data.status === 'failed') {
        setScanning(false)
        if (data.status === 'failed') {
          setError(data.message)
        }
      }
    } catch (err) {
      setError('Failed to get scan status')
      setScanning(false)
    }
  }, [])

  useEffect(() => {
    if (scanning && scanId) {
      const interval = setInterval(() => pollStatus(scanId), 1500)
      return () => clearInterval(interval)
    }
  }, [scanning, scanId, pollStatus])

  const startScan = async () => {
    if (!gitUrl.trim()) {
      setError('Please enter a Git URL')
      return
    }

    setError(null)
    setStatus(null)
    setScanning(true)

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ git_url: gitUrl })
      })

      if (!response.ok) throw new Error('Failed to start scan')

      const data: ScanStatus = await response.json()
      setScanId(data.scan_id)
      setStatus(data)
    } catch (err) {
      setError('Failed to start scan. Make sure the backend is running.')
      setScanning(false)
    }
  }

  const filteredFindings = status?.results?.findings.filter(f => {
    if (filterSeverity !== 'all' && f.severity !== filterSeverity) return false
    if (filterType !== 'all' && f.secret_type !== filterType) return false
    return true
  }) || []

  const uniqueTypes = [...new Set(status?.results?.findings.map(f => f.secret_type) || [])]

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
            <p>Find exposed secrets across all branches & history</p>
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
            <div className="input-group">
              <div className="input-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/>
                </svg>
              </div>
              <input
                type="url"
                placeholder="Enter public Git repository URL (e.g., https://github.com/user/repo)"
                value={gitUrl}
                onChange={(e) => setGitUrl(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && !scanning && startScan()}
                disabled={scanning}
              />
              <button 
                className="scan-button"
                onClick={startScan}
                disabled={scanning}
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

            <div className="features">
              <div className="feature">
                <span className="feature-icon">🔍</span>
                <span>All Branches</span>
              </div>
              <div className="feature">
                <span className="feature-icon">📜</span>
                <span>Full History</span>
              </div>
              <div className="feature">
                <span className="feature-icon">🔐</span>
                <span>50+ Secret Patterns</span>
              </div>
              <div className="feature">
                <span className="feature-icon">⚡</span>
                <span>Fast Analysis</span>
              </div>
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
          {scanning && status && (
            <motion.section 
              className="progress-section"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
            >
              <div className="progress-card">
                <div className="progress-header">
                  <h3>Scanning Repository</h3>
                  <span className="progress-percent">{status.progress}%</span>
                </div>
                <div className="progress-bar">
                  <motion.div 
                    className="progress-fill"
                    initial={{ width: 0 }}
                    animate={{ width: `${status.progress}%` }}
                    transition={{ duration: 0.3 }}
                  />
                </div>
                <p className="progress-message">{status.message}</p>
              </div>
            </motion.section>
          )}
        </AnimatePresence>

        {/* Results */}
        <AnimatePresence>
          {status?.results && (
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
                    <span className="summary-value">{status.results.summary.total_findings}</span>
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
                    <span className="summary-value">{status.results.summary.critical}</span>
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
                    <span className="summary-value">{status.results.summary.high}</span>
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
                    <span className="summary-value">{status.results.summary.medium}</span>
                    <span className="summary-label">Medium</span>
                  </div>
                </motion.div>

                <motion.div 
                  className="summary-card branches"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.3 }}
                >
                  <div className="summary-icon">🌿</div>
                  <div className="summary-content">
                    <span className="summary-value">{status.results.summary.branches_scanned}</span>
                    <span className="summary-label">Branches Scanned</span>
                  </div>
                </motion.div>
              </div>

              {/* Filters */}
              {status.results.findings.length > 0 && (
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
                    Showing {filteredFindings.length} of {status.results.findings.length} findings
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
                            href={getRepoFileLink(status.results.repo_url, finding.file_path, finding.line_number, finding.commit_hash)}
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
                            <span className="commit-branch">on {finding.branch}</span>
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
        <p>Git Secret Scanner — Protect your repositories from exposed credentials</p>
      </footer>
    </div>
  )
}

export default App

