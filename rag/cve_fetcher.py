import requests

def fetch_cve(cve_id: str):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    
    try:
        r = requests.get(url, timeout=10)
        data = r.json()

        vuln = data.get("vulnerabilities", [])[0]["cve"]

        description = vuln["descriptions"][0]["value"]

        metrics = vuln.get("metrics", {})
        severity = "UNKNOWN"
        score = 0

        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]
            severity = cvss.get("baseSeverity", "UNKNOWN")
            score = cvss.get("baseScore", 0)

        return {
            "cve_id": cve_id,
            "text": f"{cve_id}: {description}",
            "severity": severity,
            "score": score
        }

    except Exception as e:
        print(f"Error fetching {cve_id}: {e}")
        return None