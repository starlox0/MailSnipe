import re
import sys
import dns.resolver
import json
import hashlib
import email
import requests
from email.utils import parseaddr
import os
from datetime import datetime
import html
from bs4 import BeautifulSoup
import urllib.parse

# VirusTotal API Key 
VIRUSTOTAL_API_KEY = "9316b5a01e39bddab57087f6d1b2c43871a2c8006662bd15601d2d76953901e5"

def get_virustotal_report(sha256_hash):
    """Get VirusTotal report for a file hash"""
    if not VIRUSTOTAL_API_KEY:
        return 0
    
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "accept": "application/json"
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data["data"]["attributes"]["last_analysis_stats"].get("malicious", 0)
        return 0
    except Exception:
        return 0

def extract_domain_from_email(email_address):
    """Extract domain part from an email address"""
    if not email_address or '@' not in email_address:
        return None
    return email_address.split('@')[-1].lower()

def is_phishing_domain(domain_to_check, known_phishing_domains):
    """Check if a domain is a known phishing domain"""
    if not domain_to_check:
        return {"domain_valid": True, "spoofed": False}
    
    domain_to_check = domain_to_check.lower()
    result = {"domain_valid": True, "spoofed": False}
    
    domain_parts = domain_to_check.split('.')
    last_domain = '.'.join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain_to_check
    
    for phishing_domain in known_phishing_domains:
        if domain_to_check == phishing_domain or domain_to_check.endswith('.' + phishing_domain):
            result["domain_valid"] = False
            result["spoofed"] = True
            break
        
        phishing_parts = phishing_domain.split('.')
        phishing_last = '.'.join(phishing_parts[-2:]) if len(phishing_parts) >= 2 else phishing_domain
        if last_domain == phishing_last:
            result["domain_valid"] = False
            result["spoofed"] = True
            break
            
    return result

def extract_email_body(msg):
    """Extract the text body from an email message"""
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            
            if "attachment" not in content_disposition:
                if content_type == "text/plain":
                    body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                elif content_type == "text/html":
                    html_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    body += re.sub('<[^<]+?>', '', html_content)
    else:
        body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
    
    return body.strip()

def generate_html_report(result, report_filename):
    """Generate a highly stylized HTML report from analysis results with a download link"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risk_color = {
        "none": "bg-green-500 text-white",
        "medium": "bg-yellow-500 text-white",
        "high": "bg-red-500 text-white"
    }.get(result["risk_rating"], "bg-gray-500 text-white")
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Email Analysis Report</title>
        <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
        <style>
            body {{ font-family: 'Inter', sans-serif; }}
            .sidebar {{ transition: all 0.3s; }}
            .sidebar a:hover {{ background-color: #e5e7eb; transform: translateX(5px); }}
            .section {{ transition: opacity 0.5s; }}
            .badge {{ display: inline-flex; align-items: center; gap: 0.5rem; }}
            .btn-primary {{ background-color: #2563eb; color: white; padding: 0.5rem 1rem; border-radius: 0.375rem; transition: background-color 0.3s; }}
            .btn-primary:hover {{ background-color: #1e40af; }}
            @media (max-width: 768px) {{
                .sidebar {{ transform: translateX(-100%); position: fixed; height: 100%; z-index: 50; }}
                .sidebar.open {{ transform: translateX(0); }}
            }}
        </style>
    </head>
    <body class="bg-gray-50">
        <div class="flex min-h-screen">
            <!-- Sidebar -->
            <div class="sidebar bg-gray-800 text-white w-64 p-6 fixed md:sticky top-0 h-screen overflow-y-auto">
                <h2 class="text-2xl font-bold mb-6">Navigation</h2>
                <nav>
                    <a href="#risk-assessment" class="block py-2 px-4 rounded hover:bg-gray-700 transition-transform mb-2"><i class="fas fa-exclamation-circle mr-2"></i>Risk Assessment</a>
                    <a href="#email-details" class="block py-2 px-4 rounded hover:bg-gray-700 transition-transform mb-2"><i class="fas fa-envelope mr-2"></i>Email Details</a>
                    <a href="#security-headers" class="block py-2 px-4 rounded hover:bg-gray-700 transition-transform mb-2"><i class="fas fa-shield-alt mr-2"></i>Security Headers</a>
                    <a href="#content-analysis" class="block py-2 px-4 rounded hover:bg-gray-700 transition-transform mb-2"><i class="fas fa-file-alt mr-2"></i>Content Analysis</a>
                    <a href="#attachments" class="block py-2 px-4 rounded hover:bg-gray-700 transition-transform mb-2"><i class="fas fa-paperclip mr-2"></i>Attachments</a>
                    <a href="#email-body" class="block py-2 px-4 rounded hover:bg-gray-700 transition-transform mb-2"><i class="fas fa-comment-alt mr-2"></i>Email Body</a>
                    <a href="#errors" class="block py-2 px-4 rounded hover:bg-gray-700 transition-transform"><i class="fas fa-bug mr-2"></i>Errors</a>
                </nav>
                <button class="md:hidden absolute top-4 right-4 text-white" onclick="toggleSidebar()">
                    <i class="fas fa-times"></i>
                </button>
            </div>

            <!-- Main Content -->
            <div class="flex-1 p-6 md:p-10">
                <button class="md:hidden mb-4 text-gray-800" onclick="toggleSidebar()">
                    <i class="fas fa-bars text-2xl"></i>
                </button>
                <div class="max-w-4xl mx-auto bg-white shadow-2xl rounded-xl overflow-hidden">
                    <div class="bg-gradient-to-r from-blue-600 to-indigo-600 p-6 text-white">
                        <h1 class="text-4xl font-extrabold">Email Analysis Report</h1>
                        <p class="mt-2 text-blue-100">Generated on: {timestamp}</p>
                        <a href="reports/{html.escape(report_filename)}" download class="btn btn-primary mt-4 inline-block">
                            <i class="fas fa-download mr-2"></i>Download Full Report
                        </a>
                    </div>

                    <div class="p-8 section" id="risk-assessment">
                        <h2 class="text-2xl font-bold mb-4 text-gray-800"><i class="fas fa-exclamation-circle mr-2"></i>Risk Assessment</h2>
                        <span class="badge px-4 py-2 rounded-full {risk_color} font-semibold">
                            <i class="fas fa-{'check-circle' if result['risk_rating'] == 'none' else 'exclamation-triangle'} mr-2"></i>
                            Risk Level: {result["risk_rating"].capitalize()}
                        </span>
                    </div>

                    <div class="p-8 section border-t" id="email-details">
                        <h2 class="text-2xl font-bold mb-4 text-gray-800"><i class="fas fa-envelope mr-2"></i>Email Details</h2>
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div class="bg-gray-50 p-4 rounded-lg">
                                <p><strong>From Address:</strong> {html.escape(result["from_address"]) if result["from_address"] else "N/A"}</p>
                                <p><strong>Domain:</strong> {html.escape(result["domain"]) if result["domain"] else "N/A"}</p>
                                <p><strong>Sender IP:</strong> {html.escape(result["sender_ip"]) if result["sender_ip"] else "N/A"}</p>
                            </div>
                            <div class="bg-gray-50 p-4 rounded-lg">
                                <p><strong>SPF Valid:</strong> <span class="badge {'text-green-600' if result["spf_valid"] else 'text-red-600'}">
                                    <i class="fas fa-{'check' if result['spf_valid'] else 'times'} mr-1"></i>{str(result["spf_valid"]).capitalize()}
                                </span></p>
                                <p><strong>DMARC Valid:</strong> <span class="badge {'text-green-600' if result["dmarc_valid"] else 'text-red-600'}">
                                    <i class="fas fa-{'check' if result['dmarc_valid'] else 'times'} mr-1"></i>{str(result["dmarc_valid"]).capitalize()}
                                </span></p>
                                <p><strong>Domain Status:</strong> <span class="badge {'text-green-600' if result["domain_valid"] else 'text-red-600'}">
                                    <i class="fas fa-{'check' if result['domain_valid'] else 'times'} mr-1"></i>{'Valid' if result["domain_valid"] else 'Invalid Domain'}
                                </span></p>
                                <p><strong>Spoofed:</strong> <span class="badge {'text-red-600' if result["spoofed"] else 'text-green-600'}">
                                    <i class="fas fa-{'times' if result['spoofed'] else 'check'} mr-1"></i>{str(result["spoofed"]).capitalize()}
                                </span></p>
                            </div>
                        </div>
                    </div>

                    <div class="p-8 section border-t" id="security-headers">
                        <h2 class="text-2xl font-bold mb-4 text-gray-800"><i class="fas fa-shield-alt mr-2"></i>Security Headers</h2>
                        <div class="bg-gray-50 p-4 rounded-lg">
                            <p><strong>SPF Header:</strong> {html.escape(result["spf_header"]) if result["spf_header"] else "N/A"}</p>
                            <p><strong>DMARC Header:</strong> {html.escape(result["dmarc_header"]) if result["dmarc_header"] else "N/A"}</p>
                            <p><strong>SPF Domain:</strong> {html.escape(result["spf_domain"]) if result["spf_domain"] else "N/A"}</p>
                        </div>
                    </div>

                    <div class="p-8 section border-t" id="content-analysis">
                        <h2 class="text-2xl font-bold mb-4 text-gray-800"><i class="fas fa-file-alt mr-2"></i>Content Analysis</h2>
                        <p><strong>Urgent Content Detected:</strong> <span class="badge {'text-red-600' if result["urgent"] else 'text-green-600'}">
                            <i class="fas fa-{'exclamation-triangle' if result['urgent'] else 'check'} mr-1"></i>{str(result["urgent"]).capitalize()}
                        </span></p>
                        <h3 class="text-lg font-semibold mt-6 mb-2">Extracted Links</h3>
                        {"<p class='text-gray-600'>No links found.</p>" if not result["extracted_links"] else "".join([
                            f'<p><a href="{link["url"]}" class="text-blue-600 hover:underline" target="_blank">{html.escape(link["url"])}</a> '
                            f'{"<span class=\"text-red-600 ml-2\"><i class=\"fas fa-exclamation-circle mr-1\"></i>Insecure</span>" if link["insecure"] else ""} '
                            f'{"<span class=\"text-red-600 ml-2\"><i class=\"fas fa-exclamation-circle mr-1\"></i>Suspicious Domain</span>" if link["suspicious_domain"] else ""} '
                            f'{"<span class=\"text-red-600 ml-2\"><i class=\"fas fa-exclamation-circle mr-1\"></i>Malicious Extension</span>" if link["malicious_extension"] else ""}</p>'
                            for link in result["extracted_links"]
                        ])}
                        {"<p class='text-red-600 font-semibold mt-4'><i class='fas fa-exclamation-triangle mr-2'></i>Malicious links detected! Links include insecure, suspicious, or malicious file extensions (e.g., .exe, .zip).</p>" 
                        if any(link["insecure"] or link["suspicious_domain"] or link["malicious_extension"] for link in result["extracted_links"]) else ""}
                    </div>

                    <div class="p-8 section border-t" id="attachments">
                        <h2 class="text-2xl font-bold mb-4 text-gray-800"><i class="fas fa-paperclip mr-2"></i>Attachments</h2>
                        {"<p class='text-gray-600'>No attachments found.</p>" if not result["attachments"] else "".join([
                            f'<div class="border p-4 rounded-lg mb-4 bg-gray-50">'
                            f'<p><strong>Filename:</strong> {html.escape(attachment["filename"])}</p>'
                            f'<p><strong>SHA256 Hash:</strong> {attachment["sha256_hash"]}</p>'
                            f'<p><strong>Malicious Score:</strong> <span class="badge {"text-red-600" if attachment["malicious_score"] > 0 else "text-green-600"}">'
                            f'<i class="fas fa-{"exclamation-triangle" if attachment["malicious_score"] > 0 else "check"} mr-1"></i>{attachment["malicious_score"]}'
                            f'</span></p>'
                            f'</div>'
                            for attachment in result["attachments"]
                        ])}
                        {"<p class=\"text-red-600 font-semibold\"><i class=\"fas fa-exclamation-triangle mr-2\"></i>Malicious files detected!</p>" if result["malicious_files"] else ""}
                        {f'<p class="text-red-600 font-semibold"><i class=\"fas fa-exclamation-triangle mr-2\"></i>{html.escape(result["attachments_error"])}</p>' if result.get("attachments_error") else ""}
                    </div>

                    <div class="p-8 section border-t" id="email-body">
                        <h2 class="text-2xl font-bold mb-4 text-gray-800"><i class="fas fa-comment-alt mr-2"></i>Email Body</h2>
                        <div class="border p-6 rounded-lg bg-gray-50 whitespace-pre-wrap text-gray-700">{html.escape(result["email_body"]) if result["email_body"] else "N/A"}</div>
                    </div>

                    <div class="p-8 section border-t" id="errors">
                        <h2 class="text-2xl font-bold mb-4 text-gray-800"><i class="fas fa-bug mr-2"></i>Errors</h2>
                        {"<p class='text-gray-600'>No errors detected during analysis.</p>" if not result.get("errors") else "".join([
                            f'<p class="text-red-600"><i class="fas fa-exclamation-circle mr-2"></i>{html.escape(error)}</p>'
                            for error in result["errors"]
                        ])}
                    </div>
                </div>
            </div>
        </div>

        <script>
            function toggleSidebar() {{
                const sidebar = document.querySelector('.sidebar');
                sidebar.classList.toggle('open');
            }}
        </script>
    </body>
    </html>
    """
    return html_content

def analyze_content(content):
    """Analyze email content and return structured results"""
    result = {
        "spf_valid": False,
        "dmarc_valid": False,
        "domain_valid": False,
        "spoofed": False,
        "spf_header": "",
        "dmarc_header": "",
        "from_address": "",
        "domain": "",
        "sender_ip": "",
        "spf_domain": "",
        "dmarc_policy": "",
        "urgent": False,
        "extracted_links": [],
        "attachments": [],
        "malicious_files": [],
        "risk_rating": "none",
        "email_body": "",
        "errors": []
    }

    # Extract SPF header
    spf_header = re.search(r'Received-SPF: (.*)', content)
    if spf_header:
        result["spf_header"] = spf_header.group(1)
        result["spf_valid"] = "pass" in spf_header.group(1).lower()
        match = re.search(r'domain of (\S+)', spf_header.group(1))
        if match:
            result["spf_domain"] = match.group(1)

    # Extract DMARC results
    dmarc_match = re.search(r'dmarc=([^\s;]+)', content, re.IGNORECASE)
    if dmarc_match:
        dmarc_value = dmarc_match.group(1).upper()
        result["dmarc_header"] = dmarc_value
        result["dmarc_valid"] = ("PASS" in dmarc_value) or ("NONE" in dmarc_value)

    # Extract "From" address and domain
    from_address = re.search(r"From: (.+)", content)
    if from_address:
        result["from_address"] = parseaddr(from_address.group(1))[1]
        result["domain"] = extract_domain_from_email(result["from_address"])

    # Extract sender IP
    sender_ip = re.search(r'Received: .*?\[([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\]', content)
    if sender_ip:
        result["sender_ip"] = sender_ip.group(1)

    # Domain Validation
    try:
        if result["domain"]:
            # Check for MX records
            dns.resolver.resolve(result["domain"], "MX")
            
            # Also check for A records
            dns.resolver.resolve(result["domain"], "A")
            
            result["domain_valid"] = True
    except Exception as e:
        result["domain_valid"] = False
        result["errors"].append(f"Domain validation failed: {str(e)}")

    # Improved Spoofing Detection with SPF Check
    if result["spf_valid"] and result["spf_domain"]:
        spf_email_domain = extract_domain_from_email(result["spf_domain"])
        if spf_email_domain and spf_email_domain != result["domain"]:
            result["spoofed"] = True

    # Known Phishing Domains Check
    known_phishing_domains = ["paypal-secure.com", "login-paypal.com", "verify-paypal.net", "cloudflare.com"]
    phishing_result = is_phishing_domain(result.get("domain", ""), known_phishing_domains)
    if not phishing_result["domain_valid"]:
        result["domain_valid"] = False
        result["spoofed"] = True

    # Extract email body and analyze content
    try:
        msg = email.message_from_string(content)
        result["email_body"] = extract_email_body(msg)
        text_content = result["email_body"].lower()
    except Exception as e:
        text_content = content.split("Content-Type: application/octet-stream")[0].lower()
        result["email_body"] = text_content
        result["errors"].append(f"Email body extraction failed: {str(e)}")

    # URL Extraction
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    
    def extract_urls_from_text(text):
        """Extract URLs from plain text using regex."""
        try:
            urls = re.findall(url_pattern, text)
            # Decode URLs to handle encoded characters (e.g., %3D to =)
            return [urllib.parse.unquote(url) for url in urls]
        except Exception as e:
            result["errors"].append(f"Error extracting URLs from text: {str(e)}")
            return []
    
    def extract_urls_from_html(html_content):
        """Extract URLs from HTML content (href and src attributes)."""
        urls = []
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            # Extract from href attributes
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href:  # Ensure href is not empty
                    urls.append(urllib.parse.unquote(href))
            # Extract from src attributes
            for tag in soup.find_all(src=True):
                src = tag['src']
                if src:  # Ensure src is not empty
                    urls.append(urllib.parse.unquote(src))
        except Exception as e:
            result["errors"].append(f"HTML parsing error: {str(e)}")
        return urls
    
    # Extract from plain text
    text_urls = extract_urls_from_text(text_content)
    all_urls = text_urls.copy()
    
    # Check if content is HTML and extract additional URLs
    if "<html" in content.lower() or "<body" in content.lower():
        html_urls = extract_urls_from_html(content)
        all_urls.extend(html_urls)
    
    # Remove duplicates
    all_urls = list(set(all_urls))
    
    # Analyze each URL
    suspicious_domains = [
        'paypal-secure.com', 'login-paypal.com', 
        'verify-paypal.net', 'cloudflare.com',
        'secure-login.net', 'account-verify.com',
        'amazonsecure.com', 'appleid-verify.com',
        'microsoft-secure.com', 'bankofamerica-secure.com'
    ]
    
    # Define potentially malicious file extensions
    malicious_extensions = [
        '.zip', '.exe', '.bat', '.scr', '.pif', '.com', '.vbs',
        '.js', '.wsf', '.lnk', '.jar', '.docm', '.xlsm', '.pptm',
        '.cloudfare.io', '.bit.ly', '.tinyurl.com' , 't.co',
        '.000webhostapp.com', '.web.app'
    ]
    
    for url in all_urls:
        url = url.strip('=/"')
        if not url:  # Skip empty URLs
            continue
        
        is_http = url.startswith('http://')
        is_suspicious = any(domain in url.lower() for domain in suspicious_domains)
        # Check for malicious file extensions
        is_malicious_extension = any(url.lower().endswith(ext) for ext in malicious_extensions)
        
        result["extracted_links"].append({
            "url": url,
            "insecure": is_http,
            "suspicious_domain": is_suspicious,
            "malicious_extension": is_malicious_extension
        })

    # Urgency detection
    urgency_keywords = [
        "urgent", "immediate action required", "asap", "deadline", 
        "last chance", "respond immediately", "don't delay", 
        "act fast", "limited time", "account suspension",
        "verify now", "password expiry", "security alert",
        "user", "valued customer", "customer",
        "suspension", "24 hours", "temporary"
    ]
    result["urgent"] = any(re.search(rf"\b{re.escape(keyword)}\b", text_content, re.IGNORECASE) for keyword in urgency_keywords)

    # Extract Attachments and Check with VirusTotal
    try:
        msg = email.message_from_string(content)
        for part in msg.walk():
            if part.get_content_maintype() != 'multipart' and part.get('Content-Disposition') is not None:
                filename = part.get_filename()
                if filename:
                    payload = part.get_payload(decode=True)
                    if payload:
                        sha256_hash = hashlib.sha256(payload).hexdigest()
                        vt_result = get_virustotal_report(sha256_hash)

                        attachment_info = {
                            "filename": filename,
                            "sha256_hash": sha256_hash,
                            "malicious_score": vt_result
                        }

                        result["attachments"].append(attachment_info)
                        if vt_result > 0:
                            result["malicious_files"].append(attachment_info)
    except Exception as e:
        result["attachments_error"] = f"Error processing attachments: {str(e)}"
        result["errors"].append(f"Attachment processing failed: {str(e)}")

    # Calculate Risk Rating
    if any(link["malicious_extension"] for link in result["extracted_links"]):
        result["risk_rating"] = "high"
    else:
        risk_factors = 0
        
        if result["spoofed"]:
            risk_factors += 1
        if result["urgent"]:
            risk_factors += 1
        if any(link["insecure"] or link["suspicious_domain"] for link in result["extracted_links"]):
            risk_factors += 1
        if not result["domain_valid"]:
            risk_factors += 1
        if any(f.get('malicious_score', 0) > 0 for f in result["malicious_files"]):
            risk_factors += 3
        
        if risk_factors == 0:
            result["risk_rating"] = "none"
        elif risk_factors <= 2:
            result["risk_rating"] = "medium"
        else:
            result["risk_rating"] = "high"

    return result

def main():
    """Main function to handle script execution"""
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python email_analyzer.py <email_file>"}, indent=4))
        sys.exit(1)

    file_path = sys.argv[1]
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
        
        # Analyze email content
        analysis_result = analyze_content(content)
        
        # Create reports directory if it doesn't exist
        reports_dir = "reports"
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)
        
        # Generate report filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"email_analysis_report_{timestamp}.html"
        report_path = os.path.join(reports_dir, report_filename)
        
        # Generate HTML report with the report filename
        html_report = generate_html_report(analysis_result, report_filename)
        
        # Save HTML report
        with open(report_path, 'w', encoding='utf-8') as report_file:
            report_file.write(html_report)
        
        # Output JSON results
        print(json.dumps(analysis_result, indent=4, ensure_ascii=False))
        print(f"HTML report saved to: {report_path}", file=sys.stderr)
        
    except FileNotFoundError:
        print(json.dumps({"error": f"File '{file_path}' not found."}, indent=4))
        sys.exit(1)
    except Exception as e:
        print(json.dumps({"error": f"Analysis failed: {str(e)}"}, indent=4))
        sys.exit(1)

if __name__ == "__main__":
    main()
