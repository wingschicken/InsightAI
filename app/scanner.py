import subprocess
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

PROFILE_ARGS = {
    'fast_recon': ['-F'],
    'basic': ['-sV'],
    'top_ports': ['--top-ports', '100', '-sV'],
    'service': ['-sV'],
    'full': ['-sV', '-p-'],
    'nonadmin': ["-sT"]
}

DEFAULT_NMAP_OPTIONS = ['-oX', '-', '-Pn', '-T3', '--max-retries', '1', '--host-timeout', '30s', '--min-parallelism', '10']


def normalize_target(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme and parsed.netloc:
        return parsed.netloc
    return parsed.path


def run_nmap(target: str, profile: str) -> dict:
    host = normalize_target(target)
    args = ['nmap'] + DEFAULT_NMAP_OPTIONS + PROFILE_ARGS.get(profile, PROFILE_ARGS['basic']) + [host]
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=240)
        if completed.returncode != 0:
            return {
                'tool': 'nmap',
                'target': host,
                'profile': profile,
                'open_ports': [],
                'services': [],
                'error': completed.stderr.strip() or 'nmap failed'
            }
        return parse_nmap_xml(completed.stdout, host, profile)
    except subprocess.TimeoutExpired:
        return {
            'tool': 'nmap',
            'target': host,
            'profile': profile,
            'open_ports': [],
            'services': [],
            'error': 'nmap timed out'
        }
    except FileNotFoundError:
        return {
            'tool': 'nmap',
            'target': host,
            'profile': profile,
            'open_ports': [],
            'services': [],
            'error': 'nmap is not installed'
        }
    except Exception as exc:
        return {
            'tool': 'nmap',
            'target': host,
            'profile': profile,
            'open_ports': [],
            'services': [],
            'error': str(exc)
        }


def parse_nmap_xml(xml_output: str, host: str, profile: str) -> dict:
    ports = []
    services = []
    try:
        root = ET.fromstring(xml_output)
        for port in root.findall('.//port'):
            state = port.find('state')
            if state is None or state.attrib.get('state') != 'open':
                continue
            portid = int(port.attrib.get('portid', 0))
            service_elem = port.find('service')
            service_name = service_elem.attrib.get('name', 'unknown') if service_elem is not None else 'unknown'
            ports.append(portid)
            services.append({'port': portid, 'service': service_name})
    except ET.ParseError:
        return {
            'tool': 'nmap',
            'target': host,
            'profile': profile,
            'open_ports': [],
            'services': [],
            'error': 'failed to parse nmap XML'
        }

    return {
        'tool': 'nmap',
        'target': host,
        'profile': profile,
        'open_ports': ports,
        'services': services,
        'raw_summary': f'{len(ports)} open ports detected'
    }
