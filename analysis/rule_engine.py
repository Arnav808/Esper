def generate_findings(scan_data):
    """
    Translates raw scanner observations into actionable security findings.
    Matches FR-5 PRD specifications.
    """
    findings = []
    
    
    headers_list = scan_data.get('headers', [])
   
    if isinstance(headers_list, list):
        for header_obj in headers_list:
            if header_obj.get('status') == 'missing':
                findings.append({
                    "title": f"Missing {header_obj['header']}",
                    "severity": "Medium",
                    "category": "Security Headers"
                })
    
    
    ssl_data = scan_data.get('ssl', {})
    if ssl_data.get('error'):
         findings.append({
            "title": "SSL Connection Failure",
            "severity": "High",
            "category": "Encryption"
        })
    else:
        if not ssl_data.get('https_enabled'):
            findings.append({
                "title": "HTTPS Not Enabled",
                "severity": "High",
                "category": "Encryption"
            })
        elif not ssl_data.get('certificate_valid'):
            findings.append({
                "title": "Invalid or Expired SSL Certificate",
                "severity": "High",
                "category": "Encryption"
            })
            
    return findings