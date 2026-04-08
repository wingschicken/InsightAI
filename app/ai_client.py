import os
import json
import openai


def load_local_env(path: str = '.env') -> None:
    if not os.path.exists(path):
        return
    with open(path, 'r', encoding='utf-8') as env_file:
        for line in env_file:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key not in os.environ:
                os.environ[key] = value

load_local_env()

api_key = os.getenv('OPENAI_API_KEY') or os.getenv('AI_TOKEN')
base_url = os.getenv('OPENAI_BASE_URL') or os.getenv('AI_URL') or 'https://kurim.ithope.eu/v1'
model = os.getenv('MODEL') or 'gemma3:27b'

client = openai.OpenAI(api_key=api_key, base_url=base_url)


def analyze_scan_result(scan_report: dict) -> dict:
    if not api_key:
        return {
            'risk_level': 'unknown',
            'analysis': 'OpenAI API key is not configured.',
            'recommendations': ['Set OPENAI_API_KEY and OPENAI_BASE_URL in the environment.']
        }

    prompt = (
        'You are a security analyst. Review the following scan report and provide a concise risk summary, risk level, and remediation steps. '
        'Return ONLY valid JSON with keys: risk_level, analysis, recommendations. '
        'Do not include any other text or explanation. Example: {"risk_level": "high", "analysis": "Summary here", "recommendations": ["Step 1", "Step 2"]}\n\n'
        f'Scan report:\n{json.dumps(scan_report, indent=2)}\n'
    )

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[{'role': 'user', 'content': prompt}],
            max_tokens=400,
            temperature=0.3,
        )
        content = response.choices[0].message.content.strip()
        if content.startswith('```json') and content.endswith('```'):
            content = content[7:-3].strip()
        try:
            result = json.loads(content)
            if not isinstance(result, dict):
                raise ValueError('AI response is not a JSON object')
        except (json.JSONDecodeError, ValueError):
            result = {
                'risk_level': 'unknown',
                'analysis': content,
                'recommendations': []
            }
    except Exception as exc:
        return {
            'risk_level': 'unknown',
            'analysis': 'AI analysis could not be completed.',
            'recommendations': [str(exc)]
        }

    return {
        'risk_level': result.get('risk_level', 'unknown'),
        'analysis': result.get('analysis', ''),
        'recommendations': result.get('recommendations', [])
    }
