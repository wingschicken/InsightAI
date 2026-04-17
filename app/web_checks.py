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
    
    # If target already has scheme, use it directly
    if parsed.scheme and parsed.netloc:
        hosts.append(f'{parsed.scheme}://{parsed.netloc}')
        return hosts
    
    # Extract base host
    host = parsed.netloc or parsed.path
    
    # Check for common web ports in the nmap results
    open_ports = nmap_result.get('open_ports', [])
    services = nmap_result.get('services', [])
    
    # Build a map of port -> service name
    port_to_service = {s['port']: s['service'].lower() for s in services}
    
    # Check for HTTP/HTTPS on common ports
    common_web_ports = {
        80: 'http',
        443: 'https',
        8080: 'http',
        8443: 'https',
        8000: 'http',
        8888: 'http',
        3000: 'http',
        5000: 'http',
    }
    
    for port, default_scheme in common_web_ports.items():
        if port in open_ports:
            service_name = port_to_service.get(port, default_scheme)
            # Determine scheme based on service name or port
            if 'https' in service_name or 'ssl' in service_name or port == 443 or port == 8443:
                hosts.append(f'https://{host}:{port}' if port not in [443] else f'https://{host}')
            else:
                hosts.append(f'http://{host}:{port}' if port not in [80] else f'http://{host}')
    
    # If no web services found, don't default to anything
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
