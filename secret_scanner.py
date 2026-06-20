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
from datetime import datetime, timezone
import requests
from collections import Counter # For entropy efficiency

# --- Config ---
# Consider using a dedicated config file (e.g., YAML) for more complex settings.
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
        # Using requests here as it's a single, external notification.
        # For high-frequency notifications, consider an async lib for Telegram.
        requests.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": msg}, timeout=10)
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to send Telegram message: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred sending Telegram message: {e}")

# --- Patterns ---
# Added comments to more complex regex patterns for clarity.
PATTERNS = [
    # AWS Access Key ID: Starts with AKIA, ASIA, or A3T, followed by alphanumeric.
    (r'(?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}', 'AWS Access Key', None),
    # AWS Secret Access Key: Typically 40 characters alphanumeric, often near 'aws' keyword.
    (r'(?i)aws(.{0,20})?(?-i)["\']([0-9a-zA-Z\/+]{40})["\']', 'AWS Secret Key', None),
    # GitHub Personal Access Token: Starts with ghp_, gho_, ghu_, ghs_ or ghr_ followed by 36 chars.
    (r'(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}', 'GitHub Token', 'verify_github'),
    # Slack Legacy Token / Bot Token: xox[baprs]- followed by alphanumeric and hyphens.
    (r'xox[baprs]-[a-zA-Z0-9-]+', 'Slack Token', 'verify_slack'),
    # Stripe Live Key: sk_live_ followed by 24+ alphanumeric characters.
    (r'sk_live_[0-9a-zA-Z]{24,}', 'Stripe Live Key', 'verify_stripe'),
    # Google API Key: AIza followed by 35 alphanumeric characters and hyphens.
    (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key', 'verify_google'),
    # SSH/TLS Private Key: Standard PEM format header.
    (r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----', 'Private Key', None),
    # Generic Gift/Reward/Loyalty Key: Keywords followed by key/token/secret identifier and a long string.
    (r'(?i)(giftcard|reward|loyalty)(_key|_token|secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{32,64})["\']', 'Gift Card Key', None),
]

# Configure logging to output to stdout.
# Consider using a file handler for more robust logging in production.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

def shannon_entropy(data: str) -> float:
    """
    Calculates the Shannon entropy of a string.
    Uses collections.Counter for potentially better performance on longer strings.
    """
    if not data:
        return 0.0
    n = len(data)
    counts = Counter(data) # Efficiently counts character occurrences
    entropy = 0.0
    for count in counts.values():
        p_x = count / n
        if p_x > 0: # Avoid log(0)
            entropy -= p_x * math.log2(p_x)
    return entropy

def extract_strings_from_diff(diff_text):
    """Extracts potential secret candidates from diff lines."""
    candidates = []
    # Regex to find strings within quotes or standalone alphanumeric strings.
    # It looks for at least MIN_ENTROPY_STRING_LENGTH characters.
    token_pattern = re.compile(r'["\']([^"\']{MIN_LEN,})["\']|\b([A-Za-z0-9_\-+/=]{MIN_LEN,})\b')
    
    for line in diff_text.split('\n'):
        if line.startswith('+') and not line.startswith('+++'):
            content = line[1:].strip()
            # Use the compiled pattern, substituting the minimum length
            matches = token_pattern.findall(content.replace('MIN_LEN', str(MIN_ENTROPY_STRING_LENGTH)))
            for t in matches:
                token = t[0] if t[0] else t[1] # t[0] is from quoted string, t[1] from word match
                if len(token) >= MIN_ENTROPY_STRING_LENGTH:
                    candidates.append(token)
    return candidates

def scan_diff(diff_text):
    """Scans diff text for known patterns and high-entropy strings."""
    findings = []
    # Compile patterns for efficiency if scanned multiple times
    compiled_patterns = [(re.compile(pattern, re.IGNORECASE | re.MULTILINE), service, verifier)
                         for pattern, service, verifier in PATTERNS]

    for pattern, service, verifier in compiled_patterns:
        # re.findall can return tuples if there are capturing groups.
        # We need to extract the actual token regardless of how it's returned.
        matches = pattern.findall(diff_text)
        for match in matches:
            # If match is a tuple, extract the non-empty part that looks like a token.
            # This accounts for patterns with multiple groups.
            if isinstance(match, tuple):
                token = next((m for m in match if isinstance(m, str) and len(m) > 10), None)
            else: # If match is a string directly
                token = match
            
            if token:
                findings.append({'token': token, 'service': service, 'verifier': verifier})

    # Use a set to quickly check if a token has already been found by pattern matching.
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
        self.session = None # Session will be initialized on first use

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
        
        for attempt in range(3): # Retry mechanism
            try:
                async with self.session.get(url, params=params) as resp:
                    if resp.status == 403 and resp.headers.get('X-RateLimit-Remaining') == '0':
                        # Handle rate limiting
                        reset_time = int(resp.headers.get('X-RateLimit-Reset', time.time() + 60))
                        sleep_duration = max(reset_time - time.time(), 1)
                        logger.warning(f"Rate limited by GitHub API. Sleeping for {sleep_duration:.2f}s. Reset at: {datetime.fromtimestamp(reset_time)}")
                        await asyncio.sleep(sleep_duration)
                        continue # Retry the request after sleeping
                    
                    if resp.status != 200:
                        logger.error(f"Error fetching events. Status: {resp.status}, Response: {await resp.text()}")
                        return []
                    
                    events = await resp.json()
                    # Filter for PushEvents specifically
                    return [e for e in events if e.get('type') == 'PushEvent']
            
            except aiohttp.ClientError as e:
                logger.warning(f"Attempt {attempt+1} failed (aiohttp client error): {e}. Retrying...")
            except asyncio.TimeoutError:
                logger.warning(f"Attempt {attempt+1} failed (timeout). Retrying...")
            except Exception as e:
                logger.warning(f"Attempt {attempt+1} failed (unexpected error): {e}. Retrying...")
            
            if attempt < 2: # Wait before retrying
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
                    logger.warning(f"Commit {sha} not found in {repo}.")
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
    """
    Factory function to create verifier coroutines.
    Accepts an optional aiohttp.ClientSession to reuse.
    """
    semaphore = asyncio.Semaphore(VERIFY_CONCURRENCY)
    # Use the provided session or create a new one if none is given.
    client_session = session if session else aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10))

    async def _close_session_if_created(sess):
        """Helper to close session only if it was created within this function."""
        if sess is not session and not sess.closed:
            await sess.close()
            logger.debug("Verifier session closed.")

    async def gh_verify(token):
        """Verifies GitHub token by calling the API."""
        async with semaphore:
            try:
                async with client_session.get('https://api.github.com/user', headers={'Authorization': f'token {token}'}) as resp:
                    return resp.status == 200
            except aiohttp.ClientError as e:
                logger.warning(f"GitHub verification client error: {e}")
            except asyncio.TimeoutError:
                logger.warning("GitHub verification timed out.")
            except Exception as e:
                logger.warning(f"Unexpected error during GitHub verification: {e}")
            return False # Default to False on error

    async def slack_verify(token):
        """Verifies Slack token by calling Slack API's auth.test."""
        async with semaphore:
            try:
                async with client_session.post('https://slack.com/api/auth.test', headers={'Authorization': f'Bearer {token}'}) as resp:
                    # Check for non-2xx status or an 'ok': False response
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get('ok', False)
                    else:
                        logger.warning(f"Slack verification failed. Status: {resp.status}")
                        return False
            except aiohttp.ClientError as e:
                logger.warning(f"Slack verification client error: {e}")
            except asyncio.TimeoutError:
                logger.warning("Slack verification timed out.")
            except Exception as e:
                logger.warning(f"Unexpected error during Slack verification: {e}")
            return False

    async def stripe_verify(key):
        """Verifies Stripe key by attempting to access the balance endpoint."""
        async with semaphore:
            try:
                async with client_session.get('https://api.stripe.com/v1/balance', headers={'Authorization': f'Bearer {key}'}) as resp:
                    # Stripe returns 200 OK for valid secret keys accessing protected resources.
                    # A 401 Unauthorized indicates an invalid key.
                    return resp.status == 200
            except aiohttp.ClientError as e:
                logger.warning(f"Stripe verification client error: {e}")
            except asyncio.TimeoutError:
                logger.warning("Stripe verification timed out.")
            except Exception as e:
                logger.warning(f"Unexpected error during Stripe verification: {e}")
            return False

    async def google_verify(key):
        """
        Verifies Google API key/access token using the tokeninfo endpoint.
        NOTE: This primarily verifies OAuth 2.0 access tokens. Raw API keys
        might not be validated by this endpoint, and may require different checks.
        """
        async with semaphore:
            try:
                async with client_session.get('https://www.googleapis.com/oauth2/v1/tokeninfo', params={'access_token': key}) as resp:
                    return resp.status == 200 # 200 OK indicates a valid token
            except aiohttp.ClientError as e:
                logger.warning(f"Google verification client error: {e}")
            except asyncio.TimeoutError:
                logger.warning("Google verification timed out.")
            except Exception as e:
                logger.warning(f"Unexpected error during Google verification: {e}")
            return False
            
    return gh_verify, slack_verify, stripe_verify, google_verify, client_session

async def get_last_timestamp():
    """Reads the last processed timestamp from a file."""
    try:
        with open(LAST_TIMESTAMP_FILE, 'r') as f:
            last_ts = f.read().strip()
            # Ensure it's a valid ISO format string, fall back to current time if invalid
            datetime.fromisoformat(last_ts.replace('Z', '+00:00'))
            return last_ts
    except FileNotFoundError:
        logger.info(f"Timestamp file '{LAST_TIMESTAMP_FILE}' not found. Using current time.")
        # Return current time in ISO format with 'Z' for UTC
        return datetime.now(timezone.utc).replace(second=0, microsecond=0).isoformat() + 'Z'
    except ValueError:
        logger.warning(f"Invalid timestamp format in '{LAST_TIMESTAMP_FILE}'. Using current time.")
        return datetime.now(timezone.utc).replace(second=0, microsecond=0).isoformat() + 'Z'

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
        sys.exit(1) # Exit if essential token is missing

    # Use a single ClientSession for the GitHub API interactions
    github_client = GitHub(github_token)
    
    try:
        since_iso = await get_last_timestamp()
        logger.info(f"Fetching events since: {since_iso}")
        
        events = await github_client.fetch_events_since(since_iso)
        
        if not events:
            logger.info("No new events found. Exiting.")
            return

        logger.info(f"Fetched {len(events)} PushEvents.")
        
        # Initialize verifiers, passing the GitHub session for potential reuse.
        # verifier_session is the session created by verifier_class ONLY if it created one.
        v_gh, v_slack, v_stripe, v_google, verifier_session = await verifier_class(github_client.session)
        
        found_secrets_in_run = False
        
        for ev in events:
            repo_name = ev.get('repo', {}).get('name')
            for commit in ev.get('payload', {}).get('commits', []):
                commit_sha = commit.get('sha')
                
                if not repo_name or not commit_sha:
                    logger.warning(f"Skipping event with missing repo name or commit SHA: {ev.get('id')}")
                    continue
                    
                diff_text = await github_client.get_diff(repo_name, commit_sha)
                
                if not diff_text:
                    continue # Error logged in get_diff
                    
                findings = scan_diff(diff_text)
                
                if not findings:
                    continue # No secrets found in this diff
                    
                logger.info(f"Found {len(findings)} potential secret candidate(s) in {repo_name}@{commit_sha[:7]}")
                found_secrets_in_run = True
                
                for f in findings:
                    token_value = f['token']
                    service_name = f['service']
                    verifier_func_name = f['verifier']
                    
                    valid = None # Unknown status initially
                    
                    # Determine which verifier to use
                    if verifier_func_name == 'verify_github':
                        valid = await v_gh(token_value)
                    elif verifier_func_name == 'verify_slack':
                        valid = await v_slack(token_value)
                    elif verifier_func_name == 'verify_stripe':
                        valid = await v_stripe(token_value)
                    elif verifier_func_name == 'verify_google':
                        valid = await v_google(token_value)
                    
                    # Report findings
                    if valid is True:
                        alert_message = f"[LIVE KEY] {service_name}: {token_value} (Repo: {repo_name}, Commit: {commit_sha})"
                        logger.warning(alert_message)
                        
                        # Log live key to file
                        try:
                            with open(LOG_FILE, 'a') as lf:
                                # Store as JSON for structured logging
                                lf.write(json.dumps({'timestamp': datetime.now(timezone.utc).isoformat(), 'finding': f, 'repo': repo_name, 'commit': commit_sha}) + '\n')
                        except IOError as e:
                            logger.error(f"Failed to write to log file {LOG_FILE}: {e}")
                        
                        # Send alert to Telegram
                        send_telegram(alert_message)
                        
                    elif valid is False:
                        logger.info(f"[DEAD] {service_name}: {token_value}")
                    else: # valid is None (verifier not available or couldn't verify)
                        logger.info(f"[VERIFICATION PENDING/FAILED] {service_name}: {token_value}")

        # Update timestamp only if any secrets were found and processed
        if found_secrets_in_run:
            updated_ts = update_last_timestamp()
            if updated_ts:
                logger.info(f"Run complete. Processed events since {since_iso}. Updated timestamp to {updated_ts}")
        else:
            logger.info("No secrets requiring verification were found in new events.")

    finally:
        # Ensure sessions are closed
        await github_client.close()
        # Close the verifier_session if it was created by verifier_class
        if verifier_session is not github_client.session and verifier_session and not verifier_session.closed:
            await verifier_session.close()

    end_time = time.time()
    logger.info(f"GitHub Secret Scanner run finished. Total time: {end_time - start_time:.2f} seconds.")

if __name__ == '__main__':
    # Ensure the log file is created if it doesn't exist, and permissions are okay.
    try:
        with open(LOG_FILE, 'a'):
            pass
    except IOError as e:
        logger.error(f"Could not access log file '{LOG_FILE}': {e}. Exiting.")
        sys.exit(1)

    # Handle the case of KeyboardInterrupt gracefully
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Scanner interrupted by user. Exiting gracefully.")
        sys.exit(0)
