import os
from flask import Flask, request, jsonify

# --- Project Core Module Imports ---
from analysis.scoring import calculate_score
from ai.gemini_client import generate_security_summary

# --- NEW: Phase 4 File Exporter Import ---
from exporters.markdown_generator import save_markdown_report

# --- Phase 1 Passive Scanner Imports ---
from scanners.headers import check_security_headers
from scanners.ssl_checker import check_ssl
from scanners.tech_detector import detect_technology 

app = Flask(__name__)

def force_flat_dict(data, default_fallback):
    """
    Recursively drills down through nested arrays to extract the 
    underlying tracking data dictionary safely.
    """
    if isinstance(data, dict):
        return data
    if isinstance(data, list):
        if len(data) == 0:
            return default_fallback
        return force_flat_dict(data[0], default_fallback)
    return default_fallback

@app.route('/scan', methods=['POST'])
def scan_endpoint():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"status": "error", "message": "Missing required 'url' parameter"}), 400
    
    target_url = data['url']
    
    try:
        # 2. Execute Phase 1: Live Passive Data Collection
        raw_headers = check_security_headers(target_url)
        raw_ssl = check_ssl(target_url)
        raw_tech = detect_technology(target_url)

        # --- Bulletproof Type Flattening ---
        # Headers should remain a list for the loops
        headers_data = raw_headers if isinstance(raw_headers, list) else [raw_headers] if raw_headers else []
        if len(headers_data) > 0 and isinstance(headers_data[0], list):
            headers_data = headers_data[0] # Flatten out nested header lists if present

        # Enforce flat dictionaries for SSL and Tech metrics
        ssl_data = force_flat_dict(raw_ssl, {"certificate_valid": False, "https_enabled": False})
        tech_data = force_flat_dict(raw_tech, {"technologies": []})

        # Aggregated payload construction
        raw_scan_data = {
            "headers": headers_data,
            "ssl": ssl_data,
            "technology": tech_data
        }
        
        # 3. Execute Phase 2: Explicit Normalized Vulnerability Mapping
        findings = []
        
        # Parse Security Headers List Safely
        for h in headers_data:
            if isinstance(h, dict) and h.get("status") == "missing":
                findings.append({
                    "title": f"Missing {h.get('header')}",
                    "severity": "Medium",
                    "category": "Security Headers"
                })
                    
        # Parse SSL/TLS Encryption Dictionary Safely
        if not ssl_data.get("https_enabled"):
            findings.append({
                "title": "Unencrypted HTTP Connection Enabled",
                "severity": "High",
                "category": "SSL/TLS Configuration"
            })
        if not ssl_data.get("certificate_valid") and ssl_data.get("https_enabled"):
            findings.append({
                "title": "Invalid or Expired SSL Certificate",
                "severity": "High",
                "category": "SSL/TLS Configuration"
            })
        
        # Compute the final metric score using the updated findings matrix
        security_score = calculate_score(findings)
        
        # 4. Execute Phase 3: AI Translation Pipeline
        ai_summary = generate_security_summary(target_url, security_score, findings)
        
        # --- NEW: Execute Phase 4: File Export ---
        # Pass the target and the AI string to our new generator
        saved_file_path = save_markdown_report(target_url, ai_summary)
        
        # 5. Formulate complete integrated backend response
        response_payload = {
            "status": "completed",
            "target": target_url,
            "security_score": security_score,
            "findings": findings,
            "raw_data": raw_scan_data,
            "ai_analysis": ai_summary,
            "report_path": saved_file_path  # Tells the client exactly where the file is
        }
        
        return jsonify(response_payload), 200
        
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"status": "error", "message": f"Global Pipeline failure: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)