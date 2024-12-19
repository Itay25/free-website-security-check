import requests
import ssl
import socket
import os
from flask import Flask, request, render_template, jsonify

print("The server is up and running")
app = Flask(__name__, template_folder='templates', static_folder='static')

# Google Safe Browsing API Key
API_KEY = "AIzaSyCc7YrUqca7txmoNsUnqLX90o7bQVgWxdY"
API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


# דף הבית שמציג את הטופס
@app.route('/')
def home():
    return render_template('index.html.html')

def is_url_accessible(url):
    try:
        
        response = requests.get(url, timeout=5, allow_redirects=True)
        return response.status_code in [200, 301, 302, 403]
    except requests.exceptions.RequestException:
        return False

# פונקציה לבדיקת הפניית HTTPS
def check_https_redirect(url):
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        return response.url.lower().startswith('https://')
    except requests.exceptions.RequestException:
        return None  # ערך נטרלי במקרה של שגיאה

# פונקציה לבדיקת HSTS
def check_hsts(url):
    try:
        response = requests.get(url, timeout=10)
        return 'strict-transport-security' in response.headers
    except requests.exceptions.RequestException:
        return None  # ערך נטרלי במקרה של שגיאה

# פונקציה לבדיקת תעודת SSL
def check_ssl_certificate(url):
    try:
        host = url.replace("https://", "").replace("http://", "").split('/')[0]
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host) as s:
            s.connect((host, 443))
            cert = s.getpeercert()
        return True, cert
    except Exception as e:
        print(f"Error checking SSL for {url}: {e}")
        return None, None  # ערך נטרלי במקרה של שגיאה

# פונקציה לבדיקת הרשימה השחורה של Google Safe Browsing
def check_safe_browsing(url):
    api_key = 'AIzaSyCc7YrUqca7txmoNsUnqLX90o7bQVgWxdY'
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"

    data = {
        "client": {
            "clientId": "your-client-id",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(endpoint, json=data)
        response_json = response.json()
        if "matches" in response_json:
            return "Unsafe"
        else:
            return "Safe"
    except requests.exceptions.RequestException as e:
        print(f"Error")
        return "Not Available"

# פונקציה לניתוח CSP
def analyze_csp(csp_header):
    directives = csp_header.split(';')
    report = {}

    # פירוק הכותרת למפתחות וערכים
    for directive in directives:
        directive = directive.strip()
        if directive:
            parts = directive.split(' ', 1)  # פירוק ל-key ו-value
            key = parts[0]
            values = parts[1] if len(parts) > 1 else ""
            report[key] = values.strip()

    # ניתוח של כל אחד מה-directives שיכולים להיות
    strong_csp = True

    # בדיקת script-src
    if "script-src" in report:
        script_sources = report["script-src"]
        if "'unsafe-inline'" in script_sources or "'unsafe-eval'" in script_sources:
            strong_csp = False

    # בדיקת frame-src
    if "frame-src" in report:
        frame_sources = report["frame-src"]
        if "'none'" not in frame_sources:
            strong_csp = False

    # בדיקת form-action
    if "form-action" in report:
        form_action = report["form-action"]
        if "'none'" not in form_action:
            strong_csp = False

    # בדיקת img-src
    if "img-src" in report:
        img_sources = report["img-src"]
        if "'none'" not in img_sources:
            strong_csp = False

    # בדיקת default-src
    if "default-src" in report:
        default_sources = report["default-src"]
        if "'none'" not in default_sources:
            strong_csp = False

    # החזרת המצב הכללי של ה-CSP
    if strong_csp:
        return "Strong"
    else:
        return "No CSP - Avoid entering sensitive data"

def check_csp(url):
    try:
        response = requests.get(url, timeout=5)
        csp_header = response.headers.get('Content-Security-Policy')
        if not csp_header:
            return "No CSP - Avoid entering sensitive data"
        
        return analyze_csp(csp_header)
    except requests.exceptions.RequestException as e:
        return "Error checking CSP: " + str(e)

# פונקציה לבדיקת X-Frame-Options
def check_x_frame_options(url):
    try:
        response = requests.get(url, timeout=5)
        x_frame_options = response.headers.get('X-Frame-Options')
        
        if not x_frame_options:
            return "Not Configured - Avoid sensitive actions"
        
        # החזרת המידע על מצב ה-X-Frame-Options
        x_frame_options = x_frame_options.strip().upper()
        if x_frame_options == "DENY":
            return "DENY"
        elif x_frame_options == "SAMEORIGIN":
            return "Safe (sameorigin)"
        elif x_frame_options.startswith("ALLOW-FROM"):
            return f" Allows framing from specified origin"
        else:
            return f"Unknown or non-standard directive"
    except requests.exceptions.RequestException as e:
        return f"Error checking X-Frame-Options"

# פונקציה לבדיקת X-XSS-Protection
def check_x_xss_protection(url):
    try:
        response = requests.get(url, timeout=5)
        x_xss_protection = response.headers.get('X-XSS-Protection')
        
        if not x_xss_protection:
            return "Disabled - Avoid sharing personal info"
        
        x_xss_protection = x_xss_protection.strip().lower()
        
        if x_xss_protection == "0":
            return "Potential security risk"
        elif x_xss_protection == "1":
            return "Basic protection"
        elif x_xss_protection == "1; mode=block":
            return "Strong protection"
        elif x_xss_protection.startswith("1; report="):
            return f"Reports to: {x_xss_protection.split('=')[1]}"
        else:
            return f"Unknown"
    except requests.exceptions.RequestException as e:
        return f"Error checking X-XSS-Protection"

def calculate_security_score(ssl_status, hsts_status, https_redirect_status, safe_browsing_status, csp_status, x_frame_status, x_xss_protection_status):
    # משקלים לכל בדיקה (בין 0 ל-1)
    weights = {
        "ssl": 0.20,
        "hsts": 0.15,
        "https_redirect": 0.10,
        "safe_browsing": 0.15,
        "csp": 0.15,
        "x_frame": 0.10,
        "x_xss": 0.15
    }

    # ניקוד על בסיס הצלחה/כישלון של כל בדיקה (1 אם הצליח, 0 אם לא)
    scores = {
        "ssl": 1 if ssl_status else 0,
        "hsts": 1 if hsts_status else 0,
        "https_redirect": 1 if https_redirect_status else 0,
        "safe_browsing": 1 if safe_browsing_status == "Safe" else 0,
        "csp": 1 if csp_status == "Strong" else 0,
        "x_frame": 1 if x_frame_status != "Not Configured - Avoid sensitive actions" else 0,
        "x_xss": 1 if x_xss_protection_status != "Disabled - Avoid sharing personal info" else 0
    }

    # חישוב הציון הסופי
    total_score = sum(scores[key] * weights[key] for key in scores)
    return total_score * 100
# נתיב שמחזיר את תוצאות הבדיקה כ-JSON
@app.route('/check-url', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL entered"}), 400

    if not is_url_accessible(url):
        return jsonify({"error": "URL is not accessible"}), 400

    try:
        ssl_status = check_ssl_certificate(url)
        hsts_status = check_hsts(url)
        https_redirect_status = check_https_redirect(url)
        safe_browsing_status = check_safe_browsing(url)  # קריאת ה-API
        csp_status = check_csp(url)
        x_frame_status = check_x_frame_options(url)
        x_xss_protection_status = check_x_xss_protection(url)
        total_score = calculate_security_score(ssl_status, hsts_status, https_redirect_status, safe_browsing_status, csp_status, x_frame_status, x_xss_protection_status)

        return jsonify({
            'ssl_status': 'Valid - Secure connection' if ssl_status else 'Not valid - Avoid entering sensitive data',
            'hsts_status': 'Yes - Secure communication' if hsts_status else 'No - Site may be vulnerable',
            'https_redirect_status': 'Yes - Connection is secure' if https_redirect_status else 'No - Not secure. Use HTTPS',
            'safe_browsing': safe_browsing_status,
            'csp_status': csp_status,
            'x_frame_status': x_frame_status,
            'x_xss_protection_status': x_xss_protection_status,
            'total_score': total_score
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
