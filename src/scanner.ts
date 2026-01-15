// Secret patterns for scanning
export const SECRET_PATTERNS = [
  // API Keys
  { name: "AWS Access Key ID", pattern: /AKIA[0-9A-Z]{16}/g, severity: "critical" },
  { name: "AWS Secret Access Key", pattern: /[Aa][Ww][Ss].{0,20}['"][0-9a-zA-Z/+]{40}['"]/g, severity: "critical" },
  { name: "Google API Key", pattern: /AIza[0-9A-Za-z\-_]{35}/g, severity: "high" },
  { name: "GitHub Token", pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/g, severity: "critical" },
  { name: "GitHub OAuth", pattern: /gho_[A-Za-z0-9]{36}/g, severity: "critical" },
  { name: "Slack Token", pattern: /xox[baprs]-[0-9a-zA-Z]{10,48}/g, severity: "high" },
  { name: "Slack Webhook", pattern: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8,}\/[a-zA-Z0-9_]{24}/g, severity: "high" },
  { name: "Stripe API Key", pattern: /sk_live_[0-9a-zA-Z]{24,}/g, severity: "critical" },
  { name: "Stripe Publishable Key", pattern: /pk_live_[0-9a-zA-Z]{24,}/g, severity: "medium" },
  { name: "Twilio API Key", pattern: /SK[0-9a-fA-F]{32}/g, severity: "high" },
  { name: "SendGrid API Key", pattern: /SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}/g, severity: "high" },
  { name: "Mailgun API Key", pattern: /key-[0-9a-zA-Z]{32}/g, severity: "high" },
  { name: "npm Token", pattern: /npm_[A-Za-z0-9]{36}/g, severity: "high" },
  { name: "Discord Token", pattern: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}/g, severity: "critical" },
  { name: "Discord Webhook", pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]{18,}\/[A-Za-z0-9_-]+/g, severity: "high" },
  { name: "Telegram Bot Token", pattern: /[0-9]+:AA[0-9A-Za-z\-_]{33}/g, severity: "high" },
  { name: "Firebase URL", pattern: /https:\/\/[a-z0-9-]+\.firebaseio\.com/g, severity: "medium" },
  
  // Private Keys
  { name: "RSA Private Key", pattern: /-----BEGIN RSA PRIVATE KEY-----/g, severity: "critical" },
  { name: "OpenSSH Private Key", pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/g, severity: "critical" },
  { name: "Generic Private Key", pattern: /-----BEGIN PRIVATE KEY-----/g, severity: "critical" },
  { name: "EC Private Key", pattern: /-----BEGIN EC PRIVATE KEY-----/g, severity: "critical" },
  
  // Database Connection Strings
  { name: "MongoDB URI", pattern: /mongodb(\+srv)?:\/\/[^\s<>"']+/g, severity: "critical" },
  { name: "PostgreSQL URI", pattern: /postgres(ql)?:\/\/[^\s<>"']+/g, severity: "critical" },
  { name: "MySQL URI", pattern: /mysql:\/\/[^\s<>"']+/g, severity: "critical" },
  { name: "Redis URI", pattern: /redis:\/\/[^\s<>"']+/g, severity: "high" },
  
  // Generic Secrets
  { name: "Generic API Key", pattern: /(api[_-]?key|apikey)\s*[=:]\s*['"]?[a-zA-Z0-9_\-]{20,}['"]?/gi, severity: "high" },
  { name: "Generic Secret", pattern: /(secret|secret[_-]?key)\s*[=:]\s*['"]?[a-zA-Z0-9_\-]{20,}['"]?/gi, severity: "high" },
  { name: "Generic Password", pattern: /(password|passwd|pwd)\s*[=:]\s*['"][^'"]{8,}['"]/gi, severity: "high" },
  { name: "Generic Token", pattern: /(access[_-]?token|auth[_-]?token|bearer)\s*[=:]\s*['"]?[a-zA-Z0-9_\-\.]{20,}['"]?/gi, severity: "high" },
  { name: "Basic Auth Header", pattern: /authorization:\s*basic\s+[a-zA-Z0-9+/=]+/gi, severity: "high" },
  { name: "Bearer Token", pattern: /authorization:\s*bearer\s+[a-zA-Z0-9_\-\.]+/gi, severity: "high" },
  { name: "JWT Token", pattern: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g, severity: "high" },
  
  // Environment Variables
  { name: "Hardcoded Credentials", pattern: /(db_password|database_password|db_pass)\s*[=:]\s*['"][^'"]+['"]/gi, severity: "critical" },
  { name: "AWS Environment", pattern: /(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*['"]?[A-Za-z0-9/+=]+['"]?/gi, severity: "critical" },
];

export interface Finding {
  file_path: string;
  line_number: number;
  secret_type: string;
  secret_preview: string;
  secret_full: string;
  commit_hash: string;
  commit_author: string;
  commit_date: string;
  commit_message: string;
  branch: string;
  severity: string;
  entropy: number;
}

export interface ScanResult {
  summary: {
    total_findings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    files_scanned: number;
    commits_scanned: number;
  };
  findings: Finding[];
  repo_url: string;
}

// Parse GitHub URL to get owner and repo
export function parseGitHubUrl(url: string): { owner: string; repo: string } | null {
  const patterns = [
    /github\.com\/([^/]+)\/([^/]+?)(?:\.git)?(?:\/.*)?$/,
    /github\.com:([^/]+)\/([^/]+?)(?:\.git)?$/,
  ];
  
  for (const pattern of patterns) {
    const match = url.match(pattern);
    if (match) {
      return { owner: match[1], repo: match[2].replace('.git', '') };
    }
  }
  return null;
}

// Calculate entropy
function calculateEntropy(data: string): number {
  if (!data) return 0;
  const freq: Record<string, number> = {};
  for (const char of data) {
    freq[char] = (freq[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in freq) {
    const p = freq[char] / data.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Mask secret
function maskSecret(secret: string, visibleChars: number = 4): string {
  if (secret.length <= visibleChars) {
    return '*'.repeat(secret.length);
  }
  return secret.slice(0, visibleChars) + '*'.repeat(Math.min(secret.length - visibleChars, 40));
}

// Scan content for secrets
function scanContent(
  content: string,
  filePath: string,
  commitHash: string,
  commitAuthor: string,
  commitDate: string,
  commitMessage: string,
  branch: string
): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');
  
  lines.forEach((line, index) => {
    for (const pattern of SECRET_PATTERNS) {
      // Reset regex lastIndex
      pattern.pattern.lastIndex = 0;
      let match;
      
      while ((match = pattern.pattern.exec(line)) !== null) {
        const secretValue = match[0];
        const entropy = calculateEntropy(secretValue);
        
        findings.push({
          file_path: filePath,
          line_number: index + 1,
          secret_type: pattern.name,
          secret_preview: maskSecret(secretValue),
          secret_full: secretValue,
          commit_hash: commitHash.slice(0, 8),
          commit_author: commitAuthor,
          commit_date: commitDate,
          commit_message: commitMessage.slice(0, 100),
          branch: branch,
          severity: pattern.severity,
          entropy: Math.round(entropy * 100) / 100,
        });
      }
    }
  });
  
  return findings;
}

// Fetch with rate limit handling
async function fetchGitHub(url: string, token?: string): Promise<Response> {
  const headers: Record<string, string> = {
    'Accept': 'application/vnd.github.v3+json',
  };
  
  if (token) {
    headers['Authorization'] = `token ${token}`;
  }
  
  const response = await fetch(url, { headers });
  
  if (response.status === 403) {
    const remaining = response.headers.get('X-RateLimit-Remaining');
    if (remaining === '0') {
      throw new Error('GitHub API rate limit exceeded. Please add a GitHub token or wait.');
    }
  }
  
  return response;
}

// Get file tree recursively
async function getFileTree(
  owner: string,
  repo: string,
  branch: string,
  token?: string
): Promise<Array<{ path: string; sha: string }>> {
  const url = `https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`;
  const response = await fetchGitHub(url, token);
  
  if (!response.ok) {
    throw new Error(`Failed to fetch file tree: ${response.statusText}`);
  }
  
  const data = await response.json();
  return data.tree
    .filter((item: { type: string; path: string }) => {
      if (item.type !== 'blob') return false;
      // Filter by common file extensions that might contain secrets
      const ext = item.path.split('.').pop()?.toLowerCase() || '';
      const scanExts = ['py', 'js', 'ts', 'jsx', 'tsx', 'java', 'go', 'rb', 'php', 
        'env', 'yaml', 'yml', 'json', 'xml', 'conf', 'config', 'ini', 
        'sh', 'bash', 'properties', 'toml', 'tf', 'tfvars', 'sql', 'txt', 'cfg', 'md'];
      const scanNames = ['dockerfile', 'makefile', '.env', 'secrets', 'credentials', 'config'];
      return scanExts.includes(ext) || scanNames.includes(item.path.toLowerCase().split('/').pop() || '');
    })
    .map((item: { path: string; sha: string }) => ({ path: item.path, sha: item.sha }));
}

// Get file content
async function getFileContent(
  owner: string,
  repo: string,
  sha: string,
  token?: string
): Promise<string> {
  const url = `https://api.github.com/repos/${owner}/${repo}/git/blobs/${sha}`;
  const response = await fetchGitHub(url, token);
  
  if (!response.ok) {
    return '';
  }
  
  const data = await response.json();
  try {
    return atob(data.content);
  } catch {
    return '';
  }
}

// Get recent commits
async function getCommits(
  owner: string,
  repo: string,
  branch: string,
  token?: string,
  perPage: number = 30
): Promise<Array<{ sha: string; author: string; date: string; message: string }>> {
  const url = `https://api.github.com/repos/${owner}/${repo}/commits?sha=${branch}&per_page=${perPage}`;
  const response = await fetchGitHub(url, token);
  
  if (!response.ok) {
    return [];
  }
  
  const data = await response.json();
  return data.map((commit: {
    sha: string;
    commit: { author: { name: string; date: string }; message: string };
  }) => ({
    sha: commit.sha,
    author: commit.commit.author.name,
    date: commit.commit.author.date,
    message: commit.commit.message,
  }));
}

// Get commit diff
async function getCommitDiff(
  owner: string,
  repo: string,
  sha: string,
  token?: string
): Promise<Array<{ filename: string; patch: string }>> {
  const url = `https://api.github.com/repos/${owner}/${repo}/commits/${sha}`;
  const response = await fetchGitHub(url, token);
  
  if (!response.ok) {
    return [];
  }
  
  const data = await response.json();
  return (data.files || [])
    .filter((file: { patch?: string }) => file.patch)
    .map((file: { filename: string; patch: string }) => ({
      filename: file.filename,
      patch: file.patch,
    }));
}

// Get branches
async function getBranches(
  owner: string,
  repo: string,
  token?: string
): Promise<string[]> {
  const url = `https://api.github.com/repos/${owner}/${repo}/branches?per_page=10`;
  const response = await fetchGitHub(url, token);
  
  if (!response.ok) {
    return ['main', 'master'];
  }
  
  const data = await response.json();
  return data.map((branch: { name: string }) => branch.name);
}

// Main scan function
export async function scanRepository(
  gitUrl: string,
  token: string | undefined,
  onProgress: (message: string, progress: number) => void
): Promise<ScanResult> {
  const parsed = parseGitHubUrl(gitUrl);
  if (!parsed) {
    throw new Error('Invalid GitHub URL. Please use format: https://github.com/owner/repo');
  }
  
  const { owner, repo } = parsed;
  const allFindings: Finding[] = [];
  let filesScanned = 0;
  let commitsScanned = 0;
  
  onProgress('Fetching repository branches...', 5);
  
  // Get branches
  const branches = await getBranches(owner, repo, token);
  const mainBranch = branches.includes('main') ? 'main' : branches[0] || 'master';
  
  onProgress(`Scanning branch: ${mainBranch}...`, 10);
  
  // Get file tree
  const files = await getFileTree(owner, repo, mainBranch, token);
  onProgress(`Found ${files.length} files to scan...`, 15);
  
  // Scan current files
  const fileChunks = files.slice(0, 100); // Limit to 100 files for performance
  for (let i = 0; i < fileChunks.length; i++) {
    const file = fileChunks[i];
    const progress = 15 + Math.floor((i / fileChunks.length) * 40);
    onProgress(`Scanning file: ${file.path}`, progress);
    
    try {
      const content = await getFileContent(owner, repo, file.sha, token);
      if (content) {
        const findings = scanContent(
          content,
          file.path,
          'HEAD',
          'Current',
          new Date().toISOString(),
          'Current HEAD',
          mainBranch
        );
        allFindings.push(...findings);
        filesScanned++;
      }
    } catch {
      // Skip files that can't be read
    }
    
    // Small delay to avoid rate limiting
    if (i % 10 === 0) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }
  
  onProgress('Scanning commit history...', 60);
  
  // Get recent commits
  const commits = await getCommits(owner, repo, mainBranch, token, 30);
  
  // Scan commit diffs
  for (let i = 0; i < Math.min(commits.length, 20); i++) {
    const commit = commits[i];
    const progress = 60 + Math.floor((i / Math.min(commits.length, 20)) * 35);
    onProgress(`Scanning commit: ${commit.sha.slice(0, 8)}...`, progress);
    
    try {
      const diffs = await getCommitDiff(owner, repo, commit.sha, token);
      
      for (const diff of diffs) {
        // Extract added lines from patch
        const addedLines = diff.patch
          .split('\n')
          .filter(line => line.startsWith('+') && !line.startsWith('+++'))
          .map(line => line.slice(1))
          .join('\n');
        
        const findings = scanContent(
          addedLines,
          diff.filename,
          commit.sha,
          commit.author,
          commit.date,
          commit.message,
          mainBranch
        );
        allFindings.push(...findings);
      }
      commitsScanned++;
    } catch {
      // Skip commits that can't be read
    }
    
    // Small delay to avoid rate limiting
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  
  onProgress('Processing results...', 95);
  
  // Deduplicate findings
  const uniqueFindings = new Map<string, Finding>();
  for (const finding of allFindings) {
    const key = `${finding.file_path}:${finding.line_number}:${finding.secret_preview}`;
    if (!uniqueFindings.has(key)) {
      uniqueFindings.set(key, finding);
    }
  }
  
  const findings = Array.from(uniqueFindings.values());
  
  // Sort by severity
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  
  onProgress('Scan completed!', 100);
  
  return {
    summary: {
      total_findings: findings.length,
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
      files_scanned: filesScanned,
      commits_scanned: commitsScanned,
    },
    findings,
    repo_url: `https://github.com/${owner}/${repo}`,
  };
}
