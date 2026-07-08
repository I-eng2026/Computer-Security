import re
import pandas as pd
from urllib.parse import unquote
from html import unescape
from tqdm import tqdm #necessary for helpful progress bar/debugging when working with large files
from IPython.display import display
from tabulate import tabulate
from joblib import Parallel, delayed
import multiprocessing

tqdm.pandas()

#in effort to speed up performance we want to precompile all of our regex
KEYWORDS = [
    "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION", "FROM", "WHERE", "AND", "OR",
    "NOT", "LIKE", "JOIN", "ORDER", "GROUP", "BY", "HAVING", "TABLE", "CREATE", "ALTER"
]

SQLI_KEYWORDS = re.compile(r'\b(?:' + '|'.join(map(re.escape, KEYWORDS)) + r')\b', re.IGNORECASE)
SPECIALS = re.compile(r"|".join(map(re.escape, ["'", '"', ';', '*', '/*', '--', '#', ',', '//'])))
URL_ENC = re.compile(r"/.*%[a-fA-F0-9]{2}.*?\b")
HEX = re.compile(r"0x[a-fA-F0-9]+")
TAUTOLOGY = re.compile(r"(.+)=(?=\1)")

# Individual precompiled patterns
SCRIPT_TAG_PATTERN = re.compile(r'<\s*script.*?>.*?<\s*/\s*script\s*>', re.IGNORECASE | re.DOTALL)
ON_EVENT_PATTERN = re.compile(r'on\w+\s*=', re.IGNORECASE)
JAVASCRIPT_SCHEME_PATTERN = re.compile(r'javascript\s*:', re.IGNORECASE)
IMG_SRC_JS_PATTERN = re.compile(r'<\s*img[^>]*\s+src\s*=\s*["\']?javascript:', re.IGNORECASE)
IFRAME_TAG_PATTERN = re.compile(r'<\s*iframe.*?>', re.IGNORECASE)
ALERT_FUNC_PATTERN = re.compile(r'alert\s*\(', re.IGNORECASE)
EVAL_FUNC_PATTERN = re.compile(r'eval\s*\(', re.IGNORECASE)
DOCUMENT_COOKIE_PATTERN = re.compile(r'document\.cookie', re.IGNORECASE)

# Dictionary of patterns
XSS_PATTERNS = {
    'script_tag': SCRIPT_TAG_PATTERN,
    'on_event': ON_EVENT_PATTERN,
    'javascript_scheme': JAVASCRIPT_SCHEME_PATTERN,
    'img_src_js': IMG_SRC_JS_PATTERN,
    'iframe_tag': IFRAME_TAG_PATTERN,
    'alert_func': ALERT_FUNC_PATTERN,
    'eval_func': EVAL_FUNC_PATTERN,
    'document_cookie': DOCUMENT_COOKIE_PATTERN,
}

DOTDOT_PATTERN = re.compile(r'(\.\./|\.\.\\)+')
ENCODED_DOTDOT_PATTERN = re.compile(r'%2e%2e(?:%2f|%5c)+', re.IGNORECASE)
DOUBLE_SLASH_PATTERN = re.compile(r'/{2,}|\\{2,}')
NULL_BYTE_PATTERN = re.compile(r'%00', re.IGNORECASE)
TRAVERSAL_PATTERNS = {
    'dotdot': DOTDOT_PATTERN,
    'encoded_dotdot': ENCODED_DOTDOT_PATTERN,
    'double_slash': DOUBLE_SLASH_PATTERN,
    'null_byte': NULL_BYTE_PATTERN,
}

ETC_PASSWD_PATTERN = re.compile(r'/etc/passwd', re.IGNORECASE)
BASH_HISTORY_PATTERN = re.compile(r'\.bash_history', re.IGNORECASE)
ENV_PATTERN = re.compile(r'\.env', re.IGNORECASE)
COMMAND_INJECTION_PATTERN = re.compile(r'(\||;|&&|\$\()')
EXEC_CALLS_PATTERN = re.compile(r'(eval|exec|system|popen)\s*\(', re.IGNORECASE)
CVE_PATH_PATTERN = re.compile(r'/(wp-admin|cgi-bin|solr|shell\.php|\.git)', re.IGNORECASE)
BASE64_PATTERN = re.compile(r'(base64_decode|[A-Za-z0-9+/]{20,}={0,2})', re.IGNORECASE)

EXPLOIT_PATTERNS = {
    'etc_passwd': ETC_PASSWD_PATTERN,
    'bash_history': BASH_HISTORY_PATTERN,
    'env_file': ENV_PATTERN,
    'command_injection': COMMAND_INJECTION_PATTERN,
    'exec_call': EXEC_CALLS_PATTERN,
    'cve_path': CVE_PATH_PATTERN,
    'base64_payload': BASE64_PATTERN,
}

FORCEFUL_BROWSING_PATTERN = re.compile(
    r'/(admin|config|debug|hidden|private|backup|\.git|\.env|\.DS_Store|web-inf|\.htaccess)', 
    re.IGNORECASE
)

def parallel_detect_sqli(urls: pd.Series, n_jobs=multiprocessing.cpu_count()) -> pd.Series:
    """Gives us a big performance boost"""
    results = Parallel(n_jobs=n_jobs)(
        delayed(detect_sqli)(url) for url in tqdm(urls)
    )
    return pd.Series(results, index=urls.index)

def detect_sqli(url: str) -> dict:
    """Returns a dict of all the detected sqli in the current url"""

    #rapid search for any matches set true if found and categorizes accordingly
    flags = {
        'hex': bool(HEX.search(url)),
        'taut': bool(TAUTOLOGY.search(url)),
        'kw': bool(SQLI_KEYWORDS.search(url)),
        'kw_enc': False  #encoding/decoding operations proved to be slow so it is processed separately 
    }

    if URL_ENC.search(url):
        try:
            decoded = unquote(url)
            if SQLI_KEYWORDS.search(decoded):
                flags['kw_enc'] = True
        except Exception:
            pass

    return flags

def detect_csrf(request: str) -> dict:
    """Parses a request string and returns CSRF-related flags."""

    #print(f"request: {request}")
    # Split lines and parse
    words = request.strip().split()
    #print(f"lines: {words}")
    method, url =words[0].strip(),words[1].strip()  
    headers = {}

    # Try to recover key-value headers from broken space-delimited format
    for i in range(2, len(words) - 1):
        if ':' in words[i]:
            key = words[i].rstrip(':').lower()
            value = words[i + 1]
            headers[key] = value

    #we flag any state changing request
    state_changing = method in ['POST', 'PUT', 'DELETE', 'PATCH']

    # Token check
    has_csrf_token = any(k in headers for k in ['x-csrf-token', 'csrf-token', 'x-xsrf-token'])
    has_origin = 'origin' in headers
    has_referer = 'referer' in headers

    # If both 'host' and 'referer' are present, and the domain in the referer does not match the host header, flag as suspicious
    suspicious_referer = False
    if has_referer and 'host' in headers:
        referer_host_match = re.search(r'https?://([^/]+)', headers['referer'])
        if referer_host_match:
            referer_host = referer_host_match.group(1).lower()
            if referer_host != headers['host'].lower():
                suspicious_referer = True

    return {
        'state_changing': state_changing,
        'missing_csrf_token': state_changing and not has_csrf_token,
        'missing_origin_or_referer': state_changing and not (has_origin or has_referer),
        'referer_mismatch': state_changing and suspicious_referer,
        'csrf_suspected': (
            state_changing and (
                not has_csrf_token or
                not (has_origin or has_referer) or
                suspicious_referer
            )
        ),
        'url': url
    }

def detect_xss(url: str) -> dict:
    """Scans a URL for common XSS patterns and returns matching flags as a dictionary"""
    try:
        url = unescape(unquote(url))  # decode %xx and HTML entities
    except Exception:
        pass  # fail-safe fallback

    #if we find any of our xss patterns we set the type of xss to true
    return {name: bool(pattern.search(url)) for name, pattern in XSS_PATTERNS.items()}

def detect_traversal(url: str) -> dict:
    """Detects directory traversal attempts using dot-dot, encoded paths, or null bytes."""
    try:
        url = unquote(url)
    except Exception:
        pass

    #if we find any of our dir traversal patterns we set the type of dir traversal to true
    return {name: bool(pattern.search(url)) for name, pattern in TRAVERSAL_PATTERNS.items()}

def detect_exploit(url: str) -> dict:
    """Scans input for exploit patterns like RCE, LFI, or encoded payloads."""
    try:
        url = unquote(url)
    except Exception:
        pass
    return {name: bool(pattern.search(url)) for name, pattern in EXPLOIT_PATTERNS.items()}

def detect_forceful_browsing(url: str) -> dict:
    """Scans a URL for common patterns and returns matching flags as a dictionary"""
    try:
        url = unquote(url)
    except:
        pass
    return {'forceful_browsing': bool(FORCEFUL_BROWSING_PATTERN.search(url))}


def detect_ddos(df: pd.DataFrame, time_window='60s', threshold=50) -> pd.Series:
    """
    Returns a Series of dictionaries with 'ddos_flag' per row based on actual_ip and timestamp.
    """
    if 'datetime' not in df:
        df.loc[:, 'datetime'] = pd.to_datetime(df['timestamp'], errors='coerce')

    valid_df = df[df['datetime'].notna()].set_index('datetime')

    request_counts = (
        valid_df.groupby('actual_ip')['request_url']
                .rolling(time_window)
                .count()
                .reset_index(name='req_per_window')
    )

    ddos_ips = request_counts[request_counts['req_per_window'] >= threshold]['actual_ip'].unique()

    return df['actual_ip'].map(lambda ip: {'ddos_flag': ip in ddos_ips})

def report(df: pd.DataFrame, *all_findings: pd.Series) -> (pd.DataFrame, pd.DataFrame):
    """
    Generates a detailed and summarized report of threat detections.
    - Detailed: Original input + flag columns + labels.
    - Summarized: 'ident' + unique labels per row.
    """
    # Merge all findings
    detection_df = pd.concat([pd.DataFrame(f.tolist()) for f in all_findings], axis=1)
    detection_df = detection_df.loc[:, ~detection_df.columns.duplicated()]

    combined = pd.concat([df.reset_index(drop=True), detection_df.reset_index(drop=True)], axis=1)

    # Threat mapping
    threat_map = {
        'csrf_suspected': 'CSRF',
        'ddos_flag': 'DDOS',
        'forceful_browsing': 'FB',
        'hex': 'SQLi',
        'taut': 'SQLi',
        'kw': 'SQLi',
        'kw_enc': 'SQLi',
        'script_tag': 'XSS',
        'on_event': 'XSS',
        'javascript_scheme': 'XSS',
        'img_src_js': 'XSS',
        'iframe_tag': 'XSS',
        'alert_func': 'XSS',
        'eval_func': 'XSS',
        'document_cookie': 'XSS',
    }

    # Build threat label per row
    def extract_labels(row):
        """Extracts and concatenates threat labels from active detection flags in a DataFrame row."""
        labels = {label for col, label in threat_map.items() if row.get(col)}
        return " | ".join(sorted(labels)) if labels else None

    combined["threats_detected_label"] = combined.apply(extract_labels, axis=1)
    combined["threats_detected"] = combined["threats_detected_label"].notna().astype(int)

    # Detailed report includes all
    detailed = combined[combined["threats_detected"] > 0]

    # Summarized report includes ident + threat label
    summarized = detailed[["ident", "threats_detected_label"]].copy()

    return detailed, summarized

def load_csv_with_progress(path: str, chunksize: int = 100_000) -> pd.DataFrame:
    """Reads a large TSV file in chunks with progress and returns a cleaned DataFrame."""
    print(f"[+] Reading CSV in chunks from: {path}")
    chunks = []
    total_lines = sum(1 for _ in open(path, 'r', encoding='utf8'))
    with tqdm(total=total_lines, desc="Loading CSV") as pbar:
        for chunk in pd.read_csv(path, sep='\t', encoding='utf8', dtype='string', chunksize=chunksize):
            chunks.append(chunk)
            pbar.update(len(chunk))
    df = pd.concat(chunks, ignore_index=True)
    print(f"[+] Finished reading CSV. Total rows: {len(df)}")
    return df.dropna(subset=['request_url'])

if __name__ == "__main__":
    pd.set_option('display.max_rows', 100)
    pd.set_option('display.max_columns', None)
    pd.set_option('display.width', 200)
    pd.set_option('display.max_colwidth', None)

    print("[*] Starting threat analysis pipeline...")

    df = load_csv_with_progress("./log_file_2.csv")

    print("[*] Sanitizing urls...")
    urls = df['request_url'].str.replace(SPECIALS, '', regex=True)

    print("[*] Detecting SQLis...")
    sqli_findings = parallel_detect_sqli(urls)

    print("[*] Detecting XSS...")
    xss_findings = urls.progress_map(detect_xss)

    print("[*] Detecting Forceful Browsing...")
    fb_findings= urls.progress_map(detect_forceful_browsing)

    print("[*] Sanitizing requests...")
    requests = df['request_raw'].str.replace(SPECIALS, '', regex=True)

    print("[*] Detecting CSRF...")
    csrf_findings = requests.progress_map(detect_csrf)
    #print(csrf_findings)

    print("[*] Detecting DDOS...")
    ddos_findings = detect_ddos(df[['timestamp', 'actual_ip', 'request_url']])
    #print(ddos_findings)

    print("[*] Reporting...")
    detailed, summarized = report(df, xss_findings, sqli_findings, csrf_findings, ddos_findings, fb_findings)

    print(f"[+] Done. {len(detailed)} threats detected.")
    detailed.to_csv("reports_detailed.csv", index=False)
    summarized.to_csv("reports_summary.csv", index=False)
    print("[+] Detailed report saved to reports_detailed.csv")
    print("[+] Summary report saved to reports_summary.csv")
