import os
import requests
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

def generate_security_summary(target_url, security_score, findings):
    """
    Sends aggregated JSON findings directly to the Gemini REST API.
    Uses the x-goog-api-key header layout to support modern AQ. prefix keys.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return "### AI Generation Error\nGemini API key is missing. Please check your `.env` file configuration."

    # Standard clean endpoint without appending the key inside the query string
    endpoint = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
    
    prompt = f"""
    You are an expert senior cybersecurity consultant auditing the website: {target_url}.
    The backend engine scanned the site and generated the following data:
    - Security Score: {security_score}/100
    - Detailed Findings (JSON format): {findings}

    Provide a highly professional, human-readable executive markdown report.
    Strictly follow this layout:
    
    ## 1. Executive Summary
    (A clear explanation of what the score means and the overall health of the site.)
    
    ## 2. Key Vulnerabilities & Explanations
    (Translate each JSON finding into plain English, explaining WHY it is a threat and WHAT kind of attacks it leaves the site open to. If there are no findings, commend their defense posture.)
    
    ## 3. Actionable Remediation Plan
    (Give clear, concrete, technical steps the development team must execute to fix the detected gaps. If perfect score, give best practices for maintaining it.)
    
    Do not use conversational pleasantries like 'Sure, here is the report'. Start directly with the Markdown headings.
    """
    
    payload = {
        "contents": [{
            "parts": [{"text": prompt}]
        }]
    }

    # Pass the AQ. key directly inside the specialized header
    headers = {
        "Content-Type": "application/json",
        "x-goog-api-key": api_key
    }

    try:
        response = requests.post(endpoint, json=payload, headers=headers)
        response.raise_for_status() 
        
        data = response.json()
        return data['candidates'][0]['content']['parts'][0]['text']
        
    except requests.exceptions.RequestException as e:
        return f"### AI Generation Failure\nNetwork/API error: {str(e)}"
    except KeyError:
        return f"### AI Generation Failure\nUnexpected API response format: {response.text}"

# --- Isolated Testing Block ---
if __name__ == "__main__":
    print("Executing updated REST API test with header authentication...")
    mock_findings = [
        {"title": "Missing Content-Security-Policy", "severity": "Medium", "category": "Security Headers"},
        {"title": "Missing Strict-Transport-Security", "severity": "Medium", "category": "Security Headers"}
    ]
    
    report = generate_security_summary("https://vulnerable-test-site.com", 80, mock_findings)
    print("\n--- Gemini Output ---")
    print(report)