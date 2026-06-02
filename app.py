from flask import Flask, request, jsonify
import re 

from scanners.headers import check_security_headers
from scanners.ssl_checker import check_ssl
from scanners.tech_detector import detect_technology

app = Flask(__name__)

def is_valid_url(url):
    regex = re.compile(
        r'^https?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return url is not None and regex.search(url)

@app.route('/scan', methods=['POST'])
def scan_url():
    """Main execution pipeline."""
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({"error": "Missing 'url' in request body"}), 400
        
    target_url = data['url']
    
    if not is_valid_url(target_url):
        return jsonify({"error": "Invalid URL provided"}), 400

    headers_result = check_security_headers(target_url)
    ssl_result = check_ssl(target_url)
    tech_result = detect_technology(target_url)

    response = {
        "status": "completed",
        "target": target_url,
        "security_score": 100, 
        "findings": {
            "headers": headers_result,
            "ssl": ssl_result,
            "technologies": tech_result
        },
        "report_path": "reports/mock_report.md" 
    }
    return jsonify(response), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)