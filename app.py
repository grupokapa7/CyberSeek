#!/usr/bin/env python3

from io import BytesIO
import secrets, os, hashlib, sys
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import generate_csrf
from datetime import timedelta
from core.reccon import *
from core.MXToolBox import *
from core.KasperskyOpenTIP import *
from core.VirusTotal import *
from core.TalosIntelligence import *
from core.urlscan import *
from core.utilities import *
from core.ipinfo import *
from core.ScanIo import *
from waitress import serve

app = Flask(__name__)

config = configparser.ConfigParser()
config.read('config.ini')
minutes = int(config['cyberseek'].get('PERMANENT_SESSION_LIFETIME', 10))
listen_interface = config['cyberseek'].get('INTERFACE', '127.0.0.1')
listen_port = int(config['cyberseek'].get('PORT', 8080))
secure = config['cyberseek'].getboolean('SESSION_COOKIE_SECURE', fallback=False)
httponly = config['cyberseek'].getboolean('SESSION_COOKIE_HTTPONLY', fallback=False)
samesite = config['cyberseek'].get('SESSION_COOKIE_SAMESITE', 'Lax')
csrf_ssl = config['cyberseek'].getboolean('WTF_CSRF_SSL_STRICT', fallback=False)

csrf = CSRFProtect(app)
if 'CyberSeekKey' not in os.environ:
    generated_key = secrets.token_hex(64)
    os.environ['CyberSeekKey'] = generated_key

app.secret_key = os.environ['CyberSeekKey']

app.config.update(
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=minutes),
    SESSION_COOKIE_SECURE=secure,
    SESSION_COOKIE_HTTPONLY=httponly,
    SESSION_COOKIE_SAMESITE=samesite,
    WTF_CSRF_SSL_STRICT = csrf_ssl

)

basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'CyberSeek.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_SSL_STRICT'] = True
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False) 
    role = db.Column(db.String(10), nullable=False)


def initialize_database():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            hashed_admin_pw = generate_password_hash('arasaka')
            db.session.add(User(username='admin', password=hashed_admin_pw, role='admin'))
            db.session.commit()

@app.after_request
def set_secure_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self' https://tiles.stadiamaps.com https://*.basemaps.cartocdn.com data:;"
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com;"
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com;"
        "font-src 'self' https://fonts.gstatic.com;"
        "img-src 'self' https://tiles.stadiamaps.com https://*.basemaps.cartocdn.com https://urlscan.io/screenshots/ data:;"
    )
    return response

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard_monitoring'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session.clear()
            session.permanent = True 
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('dashboard_monitoring'))
        error = 'Invalid credentials'
    return render_template('login.html', error=error)


@app.route('/session')
def session_check():
    if 'username' not in session:
        return jsonify({"session": False}), 401
    return jsonify({"session": True}), 200


@app.route('/dashboard/monitoring')
def dashboard_monitoring():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('monitoring.html',
                           username= session['username'],
                           role=session.get('role'))

@app.route('/dashboard/settings')
def dashboard_settings():
    if 'username' not in session:
        return redirect(url_for('login'))
    tokens = {}
    tokens = utilities.get_tokens()
    return render_template('settings.html',
                           username= session['username'],
                           role=session.get('role'),
                           tokens=tokens)

@app.route('/about')
def about():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    return render_template('about.html',
                           username= session['username'],
                           role=session.get('role'))

@app.route('/dashboard/users')
def dashboard_users():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('dashboard_monitoring'))
    
    users = User.query.with_entities(User.username, User.role).all()
    return render_template('users.html',
                           username=session['username'],
                           role=session['role'],
                           users=users)


@app.route('/dashboard/update_password')
def dashboard_password():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('update_password.html',
                           username=session['username'],
                           role=session.get('role'))


@app.route('/reccon/whois',methods=['GET'])
def reccon_whois():
    if 'username' not in session:
        return redirect(url_for('login'))
        
    return render_template('reccon/whois.html')


@app.route('/reccon/dns',methods=['GET', 'POST'])
def reccon_dns():
    if 'username' not in session:
        return redirect(url_for('login'))        
    return render_template('reccon/dns.html')


@app.route('/reccon/blacklist',methods=['GET'])
def reccon_blacklist():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('reccon/blacklist.html')


@app.route('/reccon/spf_check',methods=['GET'])
def reccon_spf_check():
    if 'username' not in session:
        return redirect(url_for('login'))

    return render_template('reccon/spf.html')




@app.route('/analysis/reputation_lookup',methods=['GET'])
def analysis_reputation_lookup():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('analysis/reputationLookup.html')

@app.route('/analysis/url',methods=['GET'])
def analysis_url():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('analysis/url.html')

@app.route('/analysis/file',methods=['GET'])
def analysis_file():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('analysis/file.html')

@app.route('/api/urlscanio/quote')
def urlscanio_quote():
    if 'username' not in session:
        return redirect(url_for('login'))

    urlscanio = UrlScanIO()
    output = urlscanio.get_quote()
    return output

@app.route('/api/urlscanio/url',methods=['POST'])
def urlscanio_analysis():
    if 'username' not in session:
        return redirect(url_for('login'))

    data = request.get_json()
    if not data or 'query' not in data:
        return {"success": False, "result": "Missing query parameter"}
    
    query = data.get('query', '').strip()
    urlscanio = UrlScanIO()
    result = urlscanio.scan_url(query)
    return result

@app.route('/api/urlscanio/final_verdict',methods=['POST'])
def urlscanio_final_verdict():
    if 'username' not in session:
        return redirect(url_for('login'))

    data = request.get_json()
    if not data or 'query' not in data:
        return {"success": False, "result": "Missing query parameter"}
    
    query = data.get('query', '').strip()
    urlscanio = UrlScanIO()
    result = urlscanio.get_final_verdict(query)
    return result

@app.route('/api/urlscanio/report',methods=['POST'])
def urlscanio_report():
    if 'username' not in session:
        return redirect(url_for('login'))

    data = request.get_json()
    if not data or 'query' not in data:
        return {"success": False, "result": "Missing query parameter"}
    
    query = data.get('query', '').strip()
    urlscanio = UrlScanIO()
    result = urlscanio.get_result(query)
    return result

@app.route('/api/filescanio/file',methods=['POST'])
def filescan_file():
    uploaded_file = request.files.get('file')
    if not uploaded_file:
        return jsonify({'error': 'No file received','success':'False'}), 400
    
    uploaded_file.seek(0, 2)
    size = uploaded_file.tell()
    uploaded_file.seek(0)

    if size > 100 * 1024 * 1024:
        return jsonify({'error': 'File size exceeds 100MB','success':'False'}), 400
    
    file_content = uploaded_file.read()
    uploaded_file.stream = BytesIO(file_content)

    password = request.form.get('password')
    filename = uploaded_file.filename
    
    md5_hash = hashlib.md5(file_content).hexdigest()
    sha1_hash = hashlib.sha1(file_content).hexdigest()
    sha256_hash = hashlib.sha256(file_content).hexdigest()
    mime_type = uploaded_file.mimetype

    fileData = {
        "filename": filename,
        "mimetype":mime_type,
        "md5":md5_hash,
        "sha1":sha1_hash,
        "sha256":sha256_hash,
        "size":str(size)
    }

    output = None
    filescan = scanio_sandbox()
    output = filescan.send_file(target_file=uploaded_file,password=password)
    output["fileData"] = fileData

    return jsonify(output)

@app.route('/api/filescanio/status',methods=['POST'])
def scanio_task_status():
    if 'username' not in session:
        return redirect(url_for('login'))

    data = request.get_json()
    if not data or 'query' not in data:
        return {"success": False, "result": "Missing query parameter"}
    
    query = data.get('query', '').strip()
    scanio = scanio_sandbox()
    result = scanio.recover_status(query)
    return result

@app.route('/api/filescanio/file_report',methods=['POST'])
def scanio_file_report():
    if 'username' not in session:
        return redirect(url_for('login'))

    data = request.get_json()
    if not data or 'query' not in data:
        return {"success": False, "result": "Missing query parameter"}
    query = data.get('query', '').strip()
    scanio = scanio_sandbox()
    result = scanio.get_file_report(query)
    return result

@app.route('/api/filescanio/mitre_report',methods=['POST'])
def scanio_mitre_report():
    if 'username' not in session:
        return redirect(url_for('login'))

    data = request.get_json()
    if not data or 'query' not in data:
        return {"success": False, "result": "Missing query parameter"}
    
    query = data.get('query', '').strip()
    scanio = scanio_sandbox()
    result = scanio.get_mitre_report(query)
    return result


@app.route('/api/dns/query',methods=['POST'])
def dns_query():
    if 'username' not in session:
        return redirect(url_for('login'))

    data = request.get_json() or {}
    if not data or 'query' not in data or 'type' not in data:
        return {"success": False, "result": "Missing parameters"}
    
    query = data.get('query', '').strip()
    record_type = data.get('type', '').strip().upper()

    try:
        if record_type == 'ALL':
            output = Reconnaissance.dns_lookup_all(query)
        else:
            output = Reconnaissance.dns_lookup(query, record_type)
        return output
    except Exception as e:
        return {'error': "Internal error",'success':'False'}, 500
    

@app.route('/api/blacklist/check',methods=['POST'])
def blacklist_query():
    if 'username' not in session:
        return redirect(url_for('login'))

    data = request.get_json()
    if not data or 'query' not in data:
        return {"success": False, "result": "Missing query parameter"}
    query = data.get('query', '').strip()
    MxTool = MXToolBox()
    output = MxTool.blacklist_check(query)
    return output


@app.route('/api/spf/check',methods=['POST'])
def spf_query():
    if 'username' not in session:
        return redirect(url_for('login'))

    data = request.get_json()
    if not data or 'query' not in data:
        return {"success": False, "result": "Missing query parameter"}
    query = data.get('query', '').strip()
    MxTool = MXToolBox()
    output = MxTool.spf_check(query)
    return output


@app.route('/api/whois/query',methods=['POST'])
def whois_query():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    data = request.get_json()
    if not data or 'query' not in data:
        return {"success": False, "result": "Missing query parameter"}
    query = data.get('query', '').strip()
    output = Reconnaissance.whois_lookup(query)
    return output


@app.route('/api/stats')
def stats():
    if 'username' not in session:
        return redirect(url_for('login'))
    import psutil
    disk = psutil.disk_usage('/')
    return jsonify({
        "cpu": f"{psutil.cpu_percent()}%",
        "memory": {
            "percent": f"{psutil.virtual_memory().percent}%"
        },
        "disk": f"{disk.free // 1024**3} GB",
        "network": {
            "sent": f"{psutil.net_io_counters().bytes_sent // 1024} KB",
            "recv": f"{psutil.net_io_counters().bytes_recv // 1024} KB"
        }
    })


@app.route('/api/kaspersky/reputation', methods=['POST'])
def kaspersky_reputation_lookup():
    if 'username' not in session:
        return redirect(url_for('login'))

    data = request.get_json()

    if not data or 'query' not in data:
        return {"success": False, "result": "Missing query parameter"}
    
    query = data.get('query', '').strip()
    KOTIP = KasperskyOpenTIP()
    output = KOTIP.kaspersky_lookup(query)
    return jsonify(output) 


@app.route('/api/ipinfo/lookup', methods=['POST'])
def ipinfo_lookup():
    if 'username' not in session:
        return redirect(url_for('login'))

    data = request.get_json()
    if not data or 'query' not in data:
        return {"success": False, "result": "Missing query parameter"}
    
    query = data.get('query', '').strip()
    output = ipinfo.suggestion(query)
    return jsonify(output) 


@app.route('/api/vt/reputation', methods=['POST'])
def vt_reputation_lookup():
    if 'username' not in session:
        return redirect(url_for('login'))

    data = request.get_json()
    if not data or 'query' not in data:
        return {"success": False, "result": "Missing values"}
    
    query = data.get('query', '').strip()
    action = data.get('action', '').strip()
    VT = VirusTotal()
    output = None
    if utilities.valid_ip(query) and not action:
        output = VT.virustotal_lookup(query,isIP=True)
    elif utilities.valid_domain(query) and not action:
        output = VT.virustotal_lookup(query,isHost=True)
    elif utilities.detect_hash_type(query) and not action:
        output = VT.virustotal_lookup(query,isHash=True)

    elif utilities.detect_hash_type(query) and action=="contacted_domain":
        output = VT.virustotal_lookup(query,isHash=True,getContactedDomains=True)
    elif utilities.detect_hash_type(query) and action=="contacted_ip":
        output = VT.virustotal_lookup(query,isHash=True,getContactedIps=True)
    elif utilities.detect_hash_type(query) and action=="dropped_files":
        output = VT.virustotal_lookup(query,isHash=True,getDroppedFiles=True)

    elif utilities.valid_ip(query) and action=="resolutions":
        output = VT.virustotal_lookup(query,isIP=True,getResolutions=True)
    elif utilities.valid_ip(query) and action=="referrer_files":
        output = VT.virustotal_lookup(query,isIP=True,getReferrerFiles=True)
    elif utilities.valid_ip(query) and action=="communicating_files":
        output = VT.virustotal_lookup(query,isIP=True,getCommunicatingFiles=True)

    elif utilities.valid_domain(query) and action=="resolutions":
        output = VT.virustotal_lookup(query,isHost=True,getResolutions=True)
    elif utilities.valid_domain(query) and action=="referrer_files":
        output = VT.virustotal_lookup(query,isHost=True,getReferrerFiles=True)
    elif utilities.valid_domain(query) and action=="communicating_files":
        output = VT.virustotal_lookup(query,isHost=True,getCommunicatingFiles=True)
    elif utilities.valid_domain(query) and action=="subdomains":
        output = VT.virustotal_lookup(query,isHost=True,getSubdomains=True)
    elif utilities.valid_domain(query) and action=="siblings":
        output = VT.virustotal_lookup(query,isHost=True,getSiblings=True)

    elif utilities.valid_url(query):
        output = VT.virustotal_lookup(query,isUrl=True)

    else:
        output ={ "success":"False", "result":"Invalid input for Virus Total, try with IP, Hash, Hostname or Domain" }
    return jsonify(output) 


@app.route('/api/ct/reputation', methods=['POST'])
def ct_reputation_lookup():
    if 'username' not in session:
        return redirect(url_for('login'))

    data = request.get_json()
    if not data or 'query' not in data:
        return {"success": False, "result": "Missing query"}
    
    query = data.get('query', '').strip()
    CT = CiscoTalos()
    output = None

    if utilities.valid_ip(query):
        output = CT.reputation_lookup(query,isIP=True)
    elif utilities.valid_domain(query):
        output = CT.reputation_lookup(query,isHost=True)
    elif utilities.valid_url(query):
        output = CT.reputation_lookup(query,isHost=True)
    else:
        output ={ "success":"False", "result":"Invalid input for Cisco Talos, try with hostname, IP or Domain" }
    return jsonify(output) 


@app.route('/api/update_password', methods=['POST'])
def update_password():
    if 'username' not in session:
        return redirect(url_for('login'))

    data = request.get_json() or {}
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    confirm_password = data.get('confirm_password', '')

    if not current_password or not new_password or not confirm_password:
        return {"success": "False", "result": "Missing required fields."}

    if new_password != confirm_password:
        return {"success": "False", "result": "Passwords do not match."}
    
    user = User.query.filter_by(username=session['username']).first()
    if not user or not check_password_hash(user.password, current_password):
        return {"success": "False", "result": "Invalid current password."}
    
    user.password = generate_password_hash(new_password)
    db.session.commit()
    return {"success": "True", "result": "Password updated successfully."}


@app.route('/api/settings',methods=['POST'])
def settings_data():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('dashboard_monitoring'))
    
    data = request.get_json() or {}
    if not data:
        return {"success": "False", "result": "Missing required fields."}

    output = utilities.save_tokens(data)
    return output


@app.route('/api/user', methods=['POST'])
def admin_panel():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('dashboard_monitoring'))

    message = None
    error = None

    action = request.form.get('action')

    if action == 'create':
        new_user = request.form['new_username']
        new_pass = request.form['new_password']
        new_role = request.form['role']
        if User.query.filter_by(username=new_user).first():
            error = f"User '{new_user}' already exists."
        else:
            hashed_pass = generate_password_hash(new_pass)
            user = User(username=new_user, password=hashed_pass, role=new_role)
            db.session.add(user)
            db.session.commit()
            message = f"User '{new_user}' created."

    elif action == 'delete':
        username = request.form['username']
        if username == 'admin':
            error = "Cannot delete core admin user."
        else:
            user = User.query.filter_by(username=username).first()
            if user:
                db.session.delete(user)
                db.session.commit()
                message = f"User '{username}' deleted."

    users_list = User.query.all()
    return render_template('users.html',
                           username=session['username'],
                           role=session['role'],
                           message=message,
                           error=error,
                           users=users_list)


@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File size exceeds 100MB limit','success':'False'}), 413

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    initialize_database()
    print(f'Starting web server at {listen_interface}:{listen_port}')
    serve(app, host=listen_interface, port=listen_port)
