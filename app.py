import os
import json
import subprocess
import requests
import tempfile
import base64
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape
from flask import Flask, request, render_template, render_template_string, redirect, url_for, send_file
from flask import send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)

REPORTS_FOLDER = 'reports'
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'eml'}

VT_API_KEY = 'VIRUSTOTAL_API_KEY'
VT_HEADERS = {"x-apikey": VT_API_KEY}
VT_URL_SCAN = 'https://www.virustotal.com/api/v3/urls'

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    files = os.listdir(UPLOAD_FOLDER)
    return render_template('index.html', files=files)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file part in the request", 400

    file = request.files['file']
    if file.filename == '':
        return "No file selected", 400
    if not allowed_file(file.filename):
        return "Invalid file type. Only .txt and .eml allowed.", 400

    file.save(os.path.join(UPLOAD_FOLDER, file.filename))
    return redirect(url_for('index'))

@app.route('/delete', methods=['POST'])
def delete_file():
    filename = request.form['filename']
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    return redirect(url_for('index'))

@app.route('/analyze/<filename>', methods=['GET'])
def analyze_file(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(file_path):
        return "File not found", 404
    with open(file_path, 'r') as file:
        content = file.read()

    result = analyze_content(content) or {}
    return render_template('analyze.html', content=content, result=result, filename=filename)


@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    filename = secure_filename(filename)  # prevent path traversal
    file_path = os.path.join(UPLOAD_FOLDER, filename)

    if not os.path.exists(file_path):
        return "File not found", 404

    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True, mimetype='text/html')
    
def analyze_content(content):
    with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as tmp_file:
        tmp_file.write(content.encode('utf-8'))
        tmp_file_path = tmp_file.name

    try:
        result = subprocess.run(
            ['python3', 'external_script.py', tmp_file_path],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return {"error": "Invalid JSON output from external script"}
        else:
            return {
                "error": "Failed to analyze content",
                "details": result.stderr.strip()
            }
    except subprocess.TimeoutExpired:
        return {"error": "Analysis timed out"}
    finally:
        if os.path.exists(tmp_file_path):
            os.remove(tmp_file_path)

@app.route('/chatbot-ui')
def chatbot_ui():
    return render_template("chatbot.html")

@app.route('/chatbot', methods=['POST'])
def chatbot():
    data = request.get_json()
    user_message = data.get("message", "").lower()

    responses = {
        "hello": "Hello! How can I assist you?",
        "reports": "Go to /reports to list the available Reports",
        "how do i upload a file?": "Click on the 'Upload' button and select a .txt or .eml file.",
        "how do i delete a file?": "Go to the homepage, find your file, and click the delete button.",
        "how does the analysis work?": "We run an external script to analyze email content for potential threats.",
        "download file as xml": "Click the 'Download' button next to the file you want to save as XML."
    }

    bot_response = responses.get(user_message, "I'm sorry, I didn't understand that. Try asking something else.")
    return {"response": bot_response}

# VirusTotal URL Scanner
def vt_scan_url(url):
    try:
        # Step 1: Submit the URL for scanning
        scan_response = requests.post(VT_URL_SCAN, headers=VT_HEADERS, data={"url": url})
        if scan_response.status_code != 200:
            return {"error": f"Scan submission failed: {scan_response.status_code}"}

        # Step 2: Encode URL for fetching the scan report
        encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        report_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"

        # Step 3: Fetch report
        report_response = requests.get(report_url, headers=VT_HEADERS)
        if report_response.status_code != 200:
            return {"error": f"Failed to fetch report: {report_response.status_code}"}

        report_data = report_response.json()
        stats = report_data["data"]["attributes"]["last_analysis_stats"]

        return {
            "url": url,
            "harmless": stats["harmless"],
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "undetected": stats["undetected"],
            "status": "Malicious" if stats["malicious"] > 0 or stats["suspicious"] > 0 else "Safe"
        }

    except Exception as e:
        return {"error": str(e)}

@app.route('/url', methods=['GET', 'POST'])
def url():
    result = None
    if request.method == 'POST':
        input_url = request.form.get('url')
        if input_url:
            result = vt_scan_url(input_url)
    return render_template("url.html", result=result)
    
@app.route('/reports')
def list_reports():
    if not os.path.exists(REPORTS_FOLDER):
        os.makedirs(REPORTS_FOLDER)
    reports = [f for f in os.listdir(REPORTS_FOLDER) if f.endswith('.html')]
    return render_template("reports.html", reports=reports)

@app.route('/reports/<path:filename>')
def serve_report(filename):
    return send_from_directory(REPORTS_FOLDER, filename)

if __name__ == '__main__':
    app.run(debug=True)
