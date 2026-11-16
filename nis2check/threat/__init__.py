"""Threat-informed weighting: collect open threat data and turn it into control weights.

Sources (all public, machine-readable):
- VERIS Community Database (VCDB): how often each threat pattern appears in incidents
- MITRE ATT&CK Enterprise (STIX 2.1): which mitigations counter which techniques
- CISA Known Exploited Vulnerabilities (KEV): exploitation trend
- ENISA EU Vulnerability Database (EUVD): exploitation trend, EU source
"""
