import requests
from typing import Any


def detect_technology(url: str) -> dict[str, Any]:
    """Detect web technologies used by the target.

    Returns:
        ``{"error": None, "technologies": [...]}`` on success,
        ``{"error": "...", "technologies": []}`` on failure.
    """
    results: dict[str, Any] = {
        "technologies": [],
        "error": None,
    }
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        html_content = response.text.lower()

        #for express
        if "express" in headers_lower.get("x-powered-by", ""):
            results["technologies"].append("Express")
        #for django
        if "django" in headers_lower.get("x-powered-by", "") or "csrfmiddlewaretoken" in html_content:
            results["technologies"].append("Django")  
        #for flask
        if "werkzeug" in headers_lower.get("server", "") or "session=" in headers_lower.get("set-cookie", ""):
                 if "flask" in headers_lower.get("x-powered-by", ""):
                    results["technologies"].append("Flask")
        
        #CMS check
        #wordpress
        if "wp-content" in html_content or "wp-includes" in html_content:
            results["technologies"].append("WordPress")
        #frontend

        #next.js
        if "__next" in html_content or "data-nextjs" in html_content:
            results["technologies"].append("Next.js")
        #react
        elif "react" in html_content or "_reactroot" in html_content:
            results["technologies"].append("React")
        #angular
        if "ng-version" in html_content or "ng-app" in html_content:
            results["technologies"].append("Angular")
        #vue
        if "data-v-" in html_content or "vue" in html_content:
            if "vue.js" in html_content or "v-bind" in html_content or "v-model" in html_content:
                results["technologies"].append("Vue")
        results["technologies"] = list(set(results["technologies"]))
        return results
    except requests.exceptions.RequestException as e:
        return {"error": f"Network error during tech detection: {str(e)}", "technologies": []}
if __name__ == '__main__':
    test_url = "https://wordpress.org"
    print(f"Executing isolated Tech Sensor test for: {test_url}...\n")
    
    detected = detect_technology(test_url)
    
    import json
    print(json.dumps(detected, indent=4))