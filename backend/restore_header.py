
import os

file_path = r"c:\Users\khanj\Matrix\backend\agents\github_agent.py"

# Known good header from previous view
header = '''"""
GitHub Security Agent - Enhanced version with intelligent scanning capabilities.

Features:
- Intelligent file prioritization
- Advanced secret detection with entropy analysis
- GitHub API rate limiting and authentication
- Dependency vulnerability scanning
- Dynamic branch detection
- Performance optimizations and caching
"""
import re
import httpx
import asyncio
import hashlib
import math
from typing import List, Dict, Any, Optional, Set, Tuple, TYPE_CHECKING
from urllib.parse import urlparse
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from collections import defaultdict
import logging
from .dependency_parser import DependencyParser, ParsedDependency

from .base_agent import BaseSecurityAgent, AgentResult
from models.vulnerability import Severity, VulnerabilityType
from core.groq_client import repo_generate, groq_manager, ModelTier
from scoring import VulnerabilityContext, ConfidenceMethod

if TYPE_CHECKING:
    from core.scan_context import ScanContext

logger = logging.getLogger(__name__)


# ==================== Configuration Classes ====================

class GithubAgentConfig:
    """Configuration constants for GitHub Security Agent"""

    # API Settings
    DEFAULT_TIMEOUT = 20.0
    MAX_RETRIES = 3
    RETRY_BACKOFF_BASE = 2
    RATE_LIMIT_BUFFER = 10  # Keep this many requests in reserve

    # File Processing
    MAX_FILES_TO_SCAN = 50  # Increased from 15
    MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5MB max per file
    CONCURRENT_FILE_LIMIT = 5

    # Secret Detection
    MIN_ENTROPY_THRESHOLD = 4.5  # Shannon entropy threshold
    SECRET_MIN_LENGTH = 20
    SECRET_MAX_LENGTH = 200

    # Caching
    CACHE_TTL_SECONDS = 3600  # 1 hour
    ENABLE_CACHE = True

    # Dependency Scanning
    ENABLE_DEPENDENCY_SCAN = True
    OSV_API_URL = "https://api.osv.dev/v1/query"

    # File Priority Scores
    PRIORITY_CRITICAL = 100  # Config files with secrets
    PRIORITY_HIGH = 80  # Auth/API files
    PRIORITY_MEDIUM = 60  # Database/connection files
    PRIORITY_LOW = 40  # Regular source code
    PRIORITY_MINIMAL = 20  # Test files


class SecretPattern:
    """Enhanced secret patterns with metadata"""

    PATTERNS = [
        # Cloud Providers
        (r'AK' + r'IA[0-9A-Z]{16}', "AWS Access Key", True),
        (r'(?i)' + r'aws(.{0,20})?[\'"][0-9a-zA-Z\/+]{40}[\'"]', "AWS Secret Key", True),
        (r'AI' + r'za[0-9A-Za-z\-_]{35}', "Google API Key", True),
        (r'ya29' + r'\.[0-9A-Za-z\-_]+', "Google OAuth Token", True),

        # API Keys
        (r'sk' + r'-[a-zA-Z0-9]{48}', "OpenAI API Key", True),
        (r'sk' + r'-proj-[a-zA-Z0-9\-_]{48,}', "OpenAI Project Key", True),
        (r'sk' + r'-ant-[a-zA-Z0-9\-_]{95,}', "Anthropic API Key", True),

        # Version Control
        (r'ghp' + r'_[a-zA-Z0-9]{36}', "GitHub Personal Access Token", True),
        (r'gho_[a-zA-Z0-9]{36}', "GitHub OAuth Token", True),
        (r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}', "GitHub Fine-Grained PAT", True),
        (r'glpat' + r'-[a-zA-Z0-9\-_]{20}', "GitLab Personal Access Token", True),

        # Payment/Commerce
        (r'sk_live_[0-9a-zA-Z]{24,}', "Stripe Live Secret Key", True),
        (r'rk_live_[0-9a-zA-Z]{24,}', "Stripe Live Restricted Key", True),
        (r'sq0csp' + r'-[0-9A-Za-z\-_]{43}', "Square Access Token", True),

        # Communication
        (r'xox' + r'[baprs]-[0-9a-zA-Z\-]{10,72}', "Slack Token", True),
        (r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+', "Slack Webhook", True),

        # Databases
        (r'post' + r'gres://[a-zA-Z0-9]+:[a-zA-Z0-9!@#$%^&*()_+=\-]+@[a-zA-Z0-9.\-]+:[0-9]+/[a-zA-Z0-9_]+',
         "PostgreSQL Connection String", True),
        (r'mongo' + r'db(\+srv)?://[a-zA-Z0-9]+:[a-zA-Z0-9!@#$%^&*()_+=\-]+@[a-zA-Z0-9.\-]+', "MongoDB Connection String",
         True),
        (r'my' + r'sql://[a-zA-Z0-9]+:[a-zA-Z0-9!@#$%^&*()_+=\-]+@[a-zA-Z0-9.\-]+:[0-9]+/[a-zA-Z0-9_]+',
         "MySQL Connection String", True),

        # Other Services
        (r'sqp' + r'_[a-zA-Z0-9]{40}', "SonarQube Token", True),
        (r'-----' + r'BEGIN (RSA |DSA |EC )?PRIVATE KEY-----', "Private Key", True),
        (r'-----' + r'BEGIN OPENSSH PRIVATE KEY-----', "OpenSSH Private Key", True),

        # JWT (with validation) - low confidence, needs entropy check
        (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+', "Potential JWT Token", False),
    ]


class DependencyFile:
    """Dependency file patterns and parsers"""

    PACKAGE_FILES = {
        'package.json': 'npm',
        'package-lock.json': 'npm',
        'yarn.lock': 'yarn',
        'requirements.txt': 'pip',
        'Pipfile': 'pip',
        'Pipfile.lock': 'pip',
        'poetry.lock': 'poetry',
        'pyproject.toml': 'poetry',
        'go.mod': 'go',
        'go.sum': 'go',
        'Gemfile': 'ruby',
        'Gemfile.lock': 'ruby',
        'composer.json': 'php',
        'composer.lock': 'php',
        'pom.xml': 'maven',
        'build.gradle': 'gradle',
        'Cargo.toml': 'rust',
        'Cargo.lock': 'rust',
    }


class NodeTaintRules:
    """Node.js/Express Taint Analysis Rules"""
    
    SOURCES = [
        'req.body', 'req.query', 'req.params', 'req.headers', 'req.cookies',
        'process.env', 'process.argv'
    ]
    
    SINKS = [
        # SQL Injection
        'sequelize.query', '.query', '.execute', '.raw', 'QueryTypes',
        # Command Injection
        'exec', 'spawn', 'execSync', 'spawnSync', 'child_process',
        # RCE / Code Injection
        'eval', 'setTimeout', 'setInterval', 'new Function', 'vm.runInContext',
        # Crypto
        'crypto.createCipher', 'jwt.sign',
        # File System
        'fs.readFile', 'fs.writeFile', 'fs.unlink'
    ]


# ==================== Data Classes ====================

@dataclass
class FileMetadata:
    """Metadata for prioritizing file scanning"""
    path: str
    priority_score: int
    file_type: str
    size: int = 0
    sha: str = ""

    def __lt__(self, other):
        """Enable sorting by priority (higher first)"""
        return self.priority_score > other.priority_score


@dataclass
class RateLimitInfo:
    """GitHub API rate limit tracking"""
    remaining: int
    limit: int
    reset_time: datetime

    @property
    def is_exhausted(self) -> bool:
        """Check if rate limit is critically low"""
        return self.remaining < GithubAgentConfig.RATE_LIMIT_BUFFER

    @property
    def seconds_until_reset(self) -> float:
        """Time until rate limit resets"""
        return max(0, (self.reset_time - datetime.now(timezone.utc)).total_seconds())


@dataclass
class SecretMatch:
    """Detected secret with metadata"""
    pattern_name: str
    value: str
    line_number: int
    entropy: float
    confidence: int
    high_confidence: bool


@dataclass
class CacheEntry:
    """Cache entry for file content"""
    content: str
    timestamp: datetime
    file_sha: str

    def is_expired(self) -> bool:
        """Check if cache entry has expired"""
        age = datetime.now(timezone.utc) - self.timestamp
        return age.total_seconds() > GithubAgentConfig.CACHE_TTL_SECONDS


# ==================== Main Agent Class ====================

'''

# Read existing file
with open(file_path, 'r', encoding='utf-8') as f:
    text = f.read()

# Find where Main Agent Class starts
marker = "# ==================== Main Agent Class ===================="
if marker in text:
    parts = text.split(marker)
    body = parts[1]
    # Reconstruct
    new_content = header + marker + body
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    print("Restored header.")
else:
    print("Marker not found, cannot restore safely.")
