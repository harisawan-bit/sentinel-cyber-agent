#!/usr/bin/env python3
"""Generate sample autonomous HTML dashboard with representative findings."""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel.core.models import Finding, Severity, FindingType
from sentinel.core.report import render

sample_findings = [
    Finding('nuclei', FindingType.VULNERABILITY, 'CVE-2024-21413 # MonikerLink', 'example.com', Severity.CRITICAL, detail='Remote Code Execution verified via Nuclei HTTP template match on /autodiscover').to_dict(),
    Finding('osv_correlate', FindingType.VULNERABILITY, 'openssl@1.1.1k', 'example.com', Severity.HIGH, detail='CVE-2023-0286 · High-severity memory corruption advisory').to_dict(),
    Finding('nuclei', FindingType.MISCONFIGURATION, 'git-config-disclosure', 'example.com', Severity.HIGH, detail='Exposed /.git/config disclosing internal repository upstream and author emails').to_dict(),
    Finding('httpx', FindingType.TECHNOLOGY, 'Apache/2.4.41 (Ubuntu)', 'example.com', Severity.MEDIUM, detail='status=200 · webserver=Apache · cdn=false').to_dict(),
    Finding('nuclei', FindingType.MISCONFIGURATION, 'missing-strict-transport-security', 'example.com', Severity.MEDIUM, detail='HTTP header Strict-Transport-Security is absent on root domain response').to_dict(),
    Finding('subfinder', FindingType.SUBDOMAIN, 'api.example.com', 'example.com', Severity.LOW, detail='Source: crt.sh passive certificate enumeration').to_dict(),
    Finding('subfinder', FindingType.SUBDOMAIN, 'staging-internal.example.com', 'example.com', Severity.LOW, detail='Source: DNS brute/passive intelligence feeds').to_dict(),
    Finding('httpx', FindingType.HOST, '93.184.216.34:443', 'example.com', Severity.LOW, detail='TLS v1.3 handshake successful · ASN: AS15133 EdgeCast').to_dict(),
    Finding('crtsh', FindingType.SUBDOMAIN, 'mail.example.com', 'example.com', Severity.INFO, detail='Logged in DigiCert Global Root G2 certificate issuance').to_dict(),
    Finding('http_probe', FindingType.TECHNOLOGY, 'HTTP/2 supported', 'example.com', Severity.INFO, detail='ALPN negotiated protocol h2 over TLS').to_dict(),
    Finding('prowler', FindingType.MISCONFIGURATION, 's3_bucket_public_read', 'aws-production-account', Severity.HIGH, detail='Bucket corp-assets-prod has public read ACL granted to Anonymous users').to_dict(),
    Finding('prowler', FindingType.MISCONFIGURATION, 'iam_root_mfa_disabled', 'aws-production-account', Severity.MEDIUM, detail='Hardware/Virtual MFA is not enforced on root account credentials').to_dict(),
    Finding('prowler', FindingType.MISCONFIGURATION, 'securitygroup_open_ssh', 'aws-production-account', Severity.MEDIUM, detail='Security Group sg-0834fa2 permits ingress 0.0.0.0/0 on TCP port 22').to_dict(),
    Finding('prowler', FindingType.MISCONFIGURATION, 'cloudwatch_alarms_unconfigured', 'aws-production-account', Severity.LOW, detail='No CloudWatch metric alarm registered for root account usage').to_dict(),
    Finding('sherlock', FindingType.ACCOUNT, 'https://github.com/target-operator', 'target-operator', Severity.LOW, detail='Profile active · verified public commit activity in infrastructure repositories').to_dict(),
    Finding('sherlock', FindingType.ACCOUNT, 'https://x.com/target-operator', 'target-operator', Severity.INFO, detail='Account presence verified · HTTP status 200 response').to_dict(),
    Finding('sherlock', FindingType.ACCOUNT, 'https://gitlab.com/target-operator', 'target-operator', Severity.INFO, detail='Public developer account registered').to_dict()
]

if __name__ == '__main__':
    html = render(sample_findings, title="Production Assessment Report")
    out_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sentinel_report_sample.html")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"Generated sample report at {out_path} ({len(html)} bytes)")
