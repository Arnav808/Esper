import os
from datetime import datetime
from urllib.parse import urlparse

def save_markdown_report(target_url, markdown_content):
    """
    Takes the AI-generated Markdown string and saves it as a physical .md file.
    """
    # 1. Ensure the 'reports' directory exists
    reports_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    # 2. Extract a clean domain name for the file name
    try:
        parsed_url = urlparse(target_url)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
        # Strip out any weird characters
        clean_domain = domain.replace(":", "_").replace("/", "_") 
    except:
        clean_domain = "unknown_target"
        
    # 3. Generate a unique, timestamped filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"security_audit_{clean_domain}_{timestamp}.md"
    filepath = os.path.join(reports_dir, filename)
    
    # 4. Write the AI analysis to the physical file
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            # Add a professional title block at the top of the document
            f.write(f"# Automated Security Audit Report\n")
            f.write(f"**Target:** `{target_url}`\n")
            f.write(f"**Scan Date:** {datetime.now().strftime('%B %d, %Y - %H:%M:%S')}\n\n")
            f.write("---\n\n")
            
            # Inject the actual Gemini AI analysis
            f.write(markdown_content)
            
        print(f"\n[+] Report successfully saved to: {filepath}")
        return filepath
        
    except Exception as e:
        print(f"\n[!] File Export Error: {str(e)}")
        return None