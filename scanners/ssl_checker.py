import ssl 
import socket 
from urllib.parse import urlparse
from datetime import datetime, timezone

def check_ssl(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or parsed_url.path
    results = {
        "https_enabled": False, 
        "certificate_valid": False 
    }
    
    if not hostname:
        results["error"] = "Invalid URL format"
        return results
        
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                results["https_enabled"] = True
                cert = secure_sock.getpeercert()
                
                not_after_str = cert['notAfter']
                
                # 1. Parse string into a naive datetime object
                expiry_date_naive = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                
                # 2. Make it timezone-aware by explicitly setting it to UTC
                expiry_date_aware = expiry_date_naive.replace(tzinfo=timezone.utc)
                
                # 3. Compare it against the modern, timezone-aware current UTC time
                if expiry_date_aware > datetime.now(timezone.utc):
                    results["certificate_valid"] = True
                    
    except socket.timeout:
        results["error"] = "connection timed out"
    except ssl.SSLError:
        results["error"] = "SSL certificate validation failed"
    except Exception as e:
        results["error"] = f"network error occurred: {str(e)}"
        
    return results 

if __name__ == "__main__":
    test_url = "https://example.com"
    print(f"Executing isolated SSL sensor test for: {test_url}...\n")
    findings = check_ssl(test_url)

    import json 
    print(json.dumps(findings, indent=4))