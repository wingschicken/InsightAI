import requests
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings()

HEADER_CHECKS = [
    ('Content-Security-Policy', 'missing_csp'),
    ('X-Frame-Options', 'missing_x_frame_options'),
    ('X-Content-Type-Options', 'missing_x_content_type_options'),
    ('Strict-Transport-Security', 'missing_hsts'),
]

SUSPICIOUS_BANNER_KEYWORDS = ['apache', 'nginx', 'iis', 'cloudflare', 'werkzeug', 'gunicorn']


def discover_web_targets(target: str, nmap_result: dict) -> list:
    parsed = urlparse(target)
    hosts = []
    if parsed.scheme and parsed.netloc:
        hosts.append(f'{parsed.scheme}://{parsed.netloc}')
    else:
        host = parsed.netloc or parsed.path
        if any(s['service'] == 'http' or s['port'] == 80 for s in nmap_result.get('services', [])):
            hosts.append(f'http://{host}')
        if any(s['service'] == 'https' or s['port'] == 443 for s in nmap_result.get('services', [])):
            hosts.append(f'https://{host}')
        if not hosts:
            hosts.append(f'http://{host}')
    return hosts


def run_web_checks(urls: list) -> dict:
    findings = []
    for url in urls:
        result = check_url(url)
        findings.extend(result.get('findings', []))
    return {
        'performed': bool(urls),
        'findings': findings,
        'urls': urls,
    }


def check_url(url: str) -> dict:
    findings = []
    try:
        response = requests.get(url, timeout=15, allow_redirects=False, verify=False)
    except Exception as exc:
        return {
            'url': url,
            'performed': False,
            'findings': [{'type': 'connection_error', 'severity': 'high', 'evidence': str(exc)}]
        }

    headers = {k.lower(): v for k, v in response.headers.items()}
    for header_name, finding_type in HEADER_CHECKS:
        if header_name.lower() not in headers:
            findings.append({
                'type': finding_type,
                'severity': 'medium',
                'evidence': f'{header_name} header is missing on {url}'
            })

    if url.startswith('http://'):
        location = headers.get('location', '')
        if not location.startswith('https://'):
            findings.append({
                'type': 'no_https_redirect',
                'severity': 'high',
                'evidence': f'{url} does not redirect to HTTPS'
            })

    cookie_header = headers.get('set-cookie', '')
    if cookie_header:
        cookie_items = cookie_header.split(',')
        for item in cookie_items:
            if 'Secure' not in item or 'HttpOnly' not in item:
                findings.append({
                    'type': 'insecure_cookie',
                    'severity': 'high',
                    'evidence': f'Cookie missing Secure or HttpOnly flags on {url}: {item.strip()}'
                })
                break

    server_banner = headers.get('server', '')
    if server_banner:
        normalized = server_banner.lower()
        if any(keyword in normalized for keyword in SUSPICIOUS_BANNER_KEYWORDS):
            findings.append({
                'type': 'suspicious_server_banner',
                'severity': 'low',
                'evidence': f'Server header reveals {server_banner} on {url}'
            })

    if not headers.get('server'):
        findings.append({
            'type': 'missing_server_header',
            'severity': 'low',
            'evidence': f'Server header not present on {url}'
        })

    return {
        'url': url,
        'performed': True,
        'status_code': response.status_code,
        'findings': findings,
    }


def build_owasp_mapping(findings: list) -> list:
    category_map = {
        'missing_csp': 'Security Misconfiguration',
        'missing_x_frame_options': 'Security Misconfiguration',
        'missing_x_content_type_options': 'Security Misconfiguration',
        'missing_hsts': 'Security Misconfiguration',
        'insecure_cookie': 'Sensitive Data Exposure',
        'no_https_redirect': 'Sensitive Data Exposure',
        'suspicious_server_banner': 'Security Misconfiguration',
        'missing_server_header': 'Security Misconfiguration',
        'connection_error': 'Security Misconfiguration',
    }
    mappings = []
    for finding in findings:
        category = category_map.get(finding.get('type'), 'Security Misconfiguration')
        mappings.append({
            'category': category,
            'evidence': finding.get('evidence', 'No detail provided')
        })
    return mappings
