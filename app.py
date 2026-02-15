from flask import Flask, render_template, request, redirect, url_for, session
import os
from scanner import scan_pcap

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Absolute upload folder (VERY IMPORTANT)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Make uploads folder if missing
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def get_default_data():
    """Return default empty data for dashboard"""
    return {
        'total_packets': 0,
        'tcp_packets': 0,
        'udp_packets': 0,
        'unique_ips': 0,
        'packets': [],
        'insecure_protocols': [],
        'port_mismatches': [],
        'vuln_tls': [],
        'unencrypted_creds': [],
        'protocol_counter': {}
    }

@app.route("/")
def dashboard():
    # Get results from session if they exist, otherwise use defaults
    results = session.pop('scan_results', None)
    
    if results:
        return render_template("dashboard.html", **results)
    else:
        return render_template("dashboard.html", **get_default_data())

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["pcap_file"]
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    # Scan the file
    results = scan_pcap(filepath)
    
    # Delete file after scanning to save space
    try:
        os.remove(filepath)
    except:
        pass
    
    # Store results in session
    session['scan_results'] = results
    
    # Redirect to dashboard
    return redirect(url_for('dashboard'))

@app.route("/vulnerabilities")
def vulnerabilities():
    return render_template("vulnerabilities.html")

@app.route("/about")
def about():
    return render_template("about.html")

if __name__ == "__main__":
    # For production on Render, use PORT environment variable
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
