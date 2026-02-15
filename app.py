from flask import Flask, render_template, request, redirect, url_for, session
import os
import sys
import traceback
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
    results = session.pop('scan_results', None)  # pop removes it after reading
    
    if results:
        return render_template("dashboard.html", **results)
    else:
        return render_template("dashboard.html", **get_default_data())

@app.route("/upload", methods=["POST"])
def upload():
    try:
        print("=" * 50, file=sys.stderr)
        print("UPLOAD STARTED", file=sys.stderr)
        print("=" * 50, file=sys.stderr)
        
        # Get the file
        file = request.files["pcap_file"]
        print(f"File received: {file.filename}", file=sys.stderr)
        
        # Save it
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)
        print(f"File saved to: {filepath}", file=sys.stderr)
        print(f"File exists: {os.path.exists(filepath)}", file=sys.stderr)
        print(f"File size: {os.path.getsize(filepath)} bytes", file=sys.stderr)

        # Scan the file
        print("Starting scan...", file=sys.stderr)
        results = scan_pcap(filepath)
        print("Scan completed successfully!", file=sys.stderr)
        print(f"Results: {results}", file=sys.stderr)
        
        # Delete file after scanning to save space
        try:
            os.remove(filepath)
            print("File deleted", file=sys.stderr)
        except Exception as e:
            print(f"Could not delete file: {e}", file=sys.stderr)
        
        # Store results in session
        session['scan_results'] = results
        
        # Redirect to dashboard
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        print("=" * 50, file=sys.stderr)
        print("ERROR OCCURRED:", file=sys.stderr)
        print(str(e), file=sys.stderr)
        print(traceback.format_exc(), file=sys.stderr)
        print("=" * 50, file=sys.stderr)
        
        # Return error to user
        error_data = get_default_data()
        session['scan_results'] = error_data
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
