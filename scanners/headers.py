import requests 

def check_security_headers(url):
    target_headers=["Content-Security-Policy","X-Frame-Options","Referrer-Policy","Strict-Transport-Security","X-Content-Type-Options"]
    results = []
    
    try:
        response = requests.get(url,timeout=5,allow_redirects=True)
        site_headers = response.headers
        
        for header in target_headers:
            if header.lower() in (h.lower() for h in site_headers.keys()):
                results.append({"header" : header, "status": "present"})
            else:
                results.append({"header" : header, "status": "missing"})
        
        # FIXED 1: Out-dented to return ONLY after the loop finishes
        return results 
        
    except requests.exceptions.Timeout:
        return[{"error": "Scan timed out. Target server took too long to respond."}]
    except requests.exceptions.RequestException as e:
        return [{"error": f"Network error occurred: {str(e)}"}]

# FIXED 2: Out-dented to the root level so the script actually triggers
if __name__ == '__main__':
    test_url = "https://example.com"
    print(f"Executing isolated sensor test for: {test_url}...\n")

    findings = check_security_headers(test_url)

    import json 
    print(json.dumps(findings,indent=4))