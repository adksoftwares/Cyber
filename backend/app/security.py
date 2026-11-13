import ipaddress, re

PATTERNS = [
    ("sql_injection", "high", re.compile(r"(union\s+select|select.+from|or\s+1=1|drop\s+table)", re.I)),
    ("xss_probe", "medium", re.compile(r"(<script|javascript:|onerror\s*=)", re.I)),
    ("path_traversal", "high", re.compile(r"(\.\./|%2e%2e%2f|/etc/passwd)", re.I)),
    ("scanner_probe", "low", re.compile(r"(wp-admin|\.env|phpmyadmin|/actuator)", re.I)),
]

def classify(target: str, detail: str):
    sample = f"{target} {detail}"
    for category, severity, pattern in PATTERNS:
        if pattern.search(sample):
            return category, severity
    return "unclassified", "low"

def valid_ip(value: str) -> str:
    return str(ipaddress.ip_address(value))
