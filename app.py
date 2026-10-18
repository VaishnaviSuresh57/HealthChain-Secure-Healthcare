from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
import os
import hashlib
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import mysql.connector
from mysql.connector import Error
from blockchain import healthchain_blockchain
from cryptography.fernet import Fernet
from security import (load_env, init_security, hash_password, verify_password, needs_rehash,
                      validate_username, validate_password, login_throttle, login_required,
                      peer_token_valid, is_valid_peer_url)

load_env()  # read .env (DB credentials, keys) before configuration is built

try:
    import ethereum_anchor
except ImportError:  # web3 not installed -> run without Ethereum anchoring
    class _NoEthereum:
        @staticmethod
        def get_network_info():
            return {"connected": False, "network": None, "latest_block": None}
        @staticmethod
        def verify_transaction(tx_hash):
            return {"verified": False, "error": "web3 not installed"}
        @staticmethod
        def store_block_hash(h):
            return None
        @staticmethod
        def get_latest_hash():
            return None
    ethereum_anchor = _NoEthereum()


# ---------------- CONFIGURATION (PHASE 24 - Production Hardening) ----------------

class Config:
    VERSION = 'HealthChain v1.0'
    DB_CONFIG = {
        'host': os.getenv("DB_HOST", "localhost"),
        'user': os.getenv("DB_USER", "root"),
        'password': os.getenv("DB_PASSWORD", ""),
        'database': os.getenv("DB_NAME", "healthchain")
    }

# Ethereum Configuration (PHASE 24)
ETHEREUM_CONFIG = {
    'ganache_url': os.getenv("GANACHE_URL", "http://127.0.0.1:7545"),
    'contract_address': os.getenv("CONTRACT_ADDRESS", "0xBCe6062C8785909e0555c59fdF059D45a364625B")
}


# ---------------- ENCRYPTION KEY MANAGEMENT ----------------

KEY_FILE = 'secret.key'

def load_or_generate_key():
    """Master key for encrypting secrets stored in the DB.
    Order: HEALTHCHAIN_ENCRYPTION_KEY env var -> secret.key file -> generate new file."""
    env_key = os.getenv("HEALTHCHAIN_ENCRYPTION_KEY")
    if env_key:
        return env_key.encode()
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read().strip()
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(key)
    try:
        os.chmod(KEY_FILE, 0o600)  # owner-only permissions
    except OSError:
        pass
    return key

# Initialize Fernet cipher
cipher_suite = Fernet(load_or_generate_key())

def encrypt_data(data):
    """Encrypt data using Fernet symmetric encryption."""
    if data:
        return cipher_suite.encrypt(data.encode()).decode()
    return data

def decrypt_data(encrypted_data):
    """Decrypt data using Fernet symmetric encryption."""
    if encrypted_data:
        try:
            return cipher_suite.decrypt(encrypted_data.encode()).decode()
        except:
            return encrypted_data
    return encrypted_data

app = Flask(__name__)
init_security(app)  # secret key, secure cookies, CSRF, security headers, error pages

# MySQL Configuration using Config class
DB_CONFIG = Config.DB_CONFIG


# ---------------- GLOBAL ERROR HANDLER ----------------

@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors."""
    return render_template('error.html'), 500


# ---------------- ABOUT ROUTE ----------------

@app.route('/about')
def about():
    """About page showing project information."""
    return render_template('about.html', version=Config.VERSION)


# ---------------- DATABASE ----------------

def get_db_connection():
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except Error as e:
        print("DB Connection Error:", e)
        return None


def init_database():
    config_without_db = {k: v for k, v in DB_CONFIG.items() if k != 'database'}

    try:
        conn = mysql.connector.connect(**config_without_db)
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_CONFIG['database']}`")
        cursor.close()
        conn.close()

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role VARCHAR(20) NOT NULL,
            public_key TEXT DEFAULT NULL,
            private_key TEXT DEFAULT NULL,
            encryption_key VARCHAR(255) DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS records (
            id INT AUTO_INCREMENT PRIMARY KEY,
            patient_username VARCHAR(100) NOT NULL,
            doctor_username VARCHAR(100) NOT NULL,
            diagnosis TEXT NOT NULL,
            prescription TEXT NOT NULL,
            signature TEXT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS access_requests (
            id INT AUTO_INCREMENT PRIMARY KEY,
            doctor_username VARCHAR(100) NOT NULL,
            patient_username VARCHAR(100) NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'Pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) NOT NULL,
            action VARCHAR(255) NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        # Migrations: add columns that older databases may be missing
        for table, column, ddl in [
            ('users', 'encryption_key', 'VARCHAR(255) DEFAULT NULL'),
            ('users', 'public_key', 'TEXT DEFAULT NULL'),
            ('users', 'private_key', 'TEXT DEFAULT NULL'),
            ('records', 'signature', 'TEXT DEFAULT NULL'),
        ]:
            cursor.execute(
                "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS "
                "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND COLUMN_NAME = %s",
                (table, column)
            )
            if cursor.fetchone()[0] == 0:
                cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")

        # Migration: encrypt any plaintext private/encryption keys already stored
        cursor.execute("SELECT id, private_key, encryption_key FROM users")
        for uid, priv, enc in cursor.fetchall():
            new_priv = encrypt_data(priv) if priv and not priv.startswith('gAAAA') else priv
            new_enc = encrypt_data(enc) if enc and not enc.startswith('gAAAA') else enc
            if (new_priv, new_enc) != (priv, enc):
                cursor.execute("UPDATE users SET private_key=%s, encryption_key=%s WHERE id=%s",
                               (new_priv, new_enc, uid))

        conn.commit()
        cursor.close()
        conn.close()

    except Error as e:
        print("DB Init Error:", e)


# ---------------- ACTIVITY LOG HELPER ----------------

def log_activity(username, action):
    """Insert an activity log entry."""
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO activity_logs (username, action) VALUES (%s, %s)",
                (username, action)
            )
            conn.commit()
            cursor.close()
            conn.close()
    except Error as e:
        print("Error logging activity:", e)


# ---------------- AUTH ----------------

@app.route('/')
def index():
    if 'user_id' in session:
        role = session.get('role')
        if role == 'patient':
            return redirect(url_for('patient_dashboard'))
        elif role == 'doctor':
            return redirect(url_for('doctor_dashboard'))
        elif role == 'admin':
            return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))


# ---------------- REGISTER ----------------

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        role = request.form.get('role', '')

        if not username or not password or not role:
            flash('All fields required')
            return render_template('register.html')

        # Only patients and doctors may self-register. Admins are created via create_admin.py
        if role not in ('patient', 'doctor'):
            flash('Invalid role')
            return render_template('register.html')

        error = validate_username(username) or validate_password(password)
        if error:
            flash(error)
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match')
            return render_template('register.html')

        hashed = hash_password(password)

        public_key = None
        private_key = None

        # Generate RSA keys ONLY for doctors
        if role == 'doctor':
            key = RSA.generate(2048)
            private_key = encrypt_data(key.export_key().decode())  # encrypted at rest
            public_key = key.publickey().export_key().decode()

        # Generate encryption key for patients
        encryption_key = None
        if role == 'patient':
            encryption_key = encrypt_data(Fernet.generate_key().decode())  # encrypted at rest

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (username, password, role, public_key, private_key, encryption_key)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (username, hashed, role, public_key, private_key, encryption_key))
            conn.commit()
            cursor.close()
            conn.close()

            flash('Registration successful')
            return redirect(url_for('login'))

        except Error:
            flash("Registration failed. Username may already be taken")

    return render_template('register.html')

# ---------------- LOGIN ----------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Username and password required')
            return render_template('login.html')

        client_ip = request.remote_addr or 'unknown'
        wait = login_throttle.seconds_locked(client_ip, username)
        if wait:
            flash(f'Too many failed attempts. Try again in {wait // 60 + 1} minute(s).')
            return render_template('login.html'), 429

        conn = get_db_connection()
        if not conn:
            flash('Database connection failed')
            return render_template('login.html')

        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()

        if user and verify_password(password, user['password']):
            login_throttle.reset(client_ip, username)
            # Upgrade legacy unsalted SHA-256 hashes to salted PBKDF2 on successful login
            if needs_rehash(user['password']):
                cursor.execute("UPDATE users SET password=%s WHERE id=%s",
                               (hash_password(password), user['id']))
                conn.commit()
            cursor.close()
            conn.close()

            session.clear()  # prevents session fixation
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']

            # Proper role-based redirect
            if user['role'] == 'patient':
                return redirect(url_for('patient_dashboard'))
            elif user['role'] == 'doctor':
                return redirect(url_for('doctor_dashboard'))
            elif user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid role detected')
                return redirect(url_for('login'))
        else:
            cursor.close()
            conn.close()
            login_throttle.record_failure(client_ip, username)
            flash('Invalid credentials')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ---------------- DASHBOARDS ----------------

@app.route('/patient_dashboard')
def patient_dashboard():
    if 'user_id' not in session or session.get('role') != 'patient':
        return redirect(url_for('login'))

    patient_username = session.get('username')
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT COUNT(*) as count FROM records WHERE patient_username = %s", (patient_username,))
    total_records = cursor.fetchone()['count']
    
    cursor.execute("""
        SELECT id, patient_username, doctor_username, diagnosis, prescription, created_at
        FROM records 
        WHERE patient_username = %s
        ORDER BY created_at DESC
        LIMIT 5
    """, (patient_username,))
    recent_records = cursor.fetchall()
    
    cursor.execute("SELECT encryption_key FROM users WHERE username = %s", (patient_username,))
    patient_info = cursor.fetchone()
    patient_key = patient_info['encryption_key'] if patient_info else None
    
    if patient_key:
        cipher = Fernet(decrypt_data(patient_key).encode())
        for record in recent_records:
            try:
                record['diagnosis'] = cipher.decrypt(record['diagnosis'].encode()).decode()
                record['prescription'] = cipher.decrypt(record['prescription'].encode()).decode()
            except:
                pass
    
    verified_records = 0
    for record in recent_records:
        record_data = (record['patient_username'] + record['doctor_username'] + 
                      record['diagnosis'] + record['prescription'])
        regenerated_hash = hashlib.sha256(record_data.encode()).hexdigest()
        
        is_verified = False
        for block in healthchain_blockchain.chain:
            if block.record_hash == regenerated_hash:
                is_verified = True
                break
        
        record['verified'] = is_verified
        if is_verified:
            verified_records += 1
    
    cursor.execute("""
        SELECT COUNT(*) as count FROM access_requests 
        WHERE patient_username = %s AND status = 'Approved'
    """, (patient_username,))
    approved_doctors = cursor.fetchone()['count']
    
    cursor.close()
    conn.close()
    
    blockchain_connected = healthchain_blockchain.get_chain_length() > 0
    
    return render_template('patient_dashboard.html', 
                          username=patient_username,
                          total_records=total_records,
                          verified_records=verified_records,
                          approved_doctors=approved_doctors,
                          recent_records=recent_records,
                          blockchain_connected=blockchain_connected)


@app.route('/doctor_dashboard')
def doctor_dashboard():
    if 'user_id' not in session or session.get('role') != 'doctor':
        return redirect(url_for('login'))

    doctor_username = session.get('username')
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT COUNT(*) as count FROM users WHERE role='patient'")
    total_patients = cursor.fetchone()['count']
    
    cursor.execute("SELECT COUNT(*) as count FROM records WHERE doctor_username=%s", (doctor_username,))
    total_records = cursor.fetchone()['count']
    
    cursor.execute("SELECT COUNT(*) as count FROM access_requests WHERE doctor_username=%s AND status='Approved'", (doctor_username,))
    approved_requests = cursor.fetchone()['count']
    
    cursor.execute("""
        SELECT r.id, r.patient_username, r.diagnosis, r.prescription, r.created_at
        FROM records r
        WHERE r.doctor_username = %s
        ORDER BY r.created_at DESC
        LIMIT 5
    """, (doctor_username,))
    recent_records = cursor.fetchall()
    
    for record in recent_records:
        cursor.execute("SELECT encryption_key FROM users WHERE username = %s", (record['patient_username'],))
        patient_info = cursor.fetchone()
        if patient_info and patient_info['encryption_key']:
            try:
                cipher = Fernet(decrypt_data(patient_info['encryption_key']).encode())
                record['diagnosis'] = cipher.decrypt(record['diagnosis'].encode()).decode()
                record['prescription'] = cipher.decrypt(record['prescription'].encode()).decode()
            except:
                pass
    
    cursor.close()
    conn.close()
    
    return render_template('doctor_dashboard.html', 
                          username=doctor_username,
                          total_patients=total_patients,
                          total_records=total_records,
                          approved_requests=approved_requests,
                          recent_records=recent_records)


# ---------------- ADMIN DASHBOARD ----------------

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    admin_username = session.get('username')
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT COUNT(*) as count FROM users")
    total_users = cursor.fetchone()['count']
    
    cursor.execute("SELECT COUNT(*) as count FROM users WHERE role='patient'")
    total_patients = cursor.fetchone()['count']
    
    cursor.execute("SELECT COUNT(*) as count FROM users WHERE role='doctor'")
    total_doctors = cursor.fetchone()['count']
    
    cursor.execute("SELECT COUNT(*) as count FROM records")
    total_records = cursor.fetchone()['count']
    
    cursor.execute("SELECT COUNT(*) as count FROM activity_logs")
    total_activity_logs = cursor.fetchone()['count']
    
    total_blocks = healthchain_blockchain.get_chain_length()
    
    cursor.execute("SELECT COUNT(*) as count FROM activity_logs WHERE action LIKE '%Tamper%'")
    result = cursor.fetchone()
    tampering_count = result['count'] if result else 0
    
    cursor.execute("SELECT COUNT(*) as count FROM activity_logs WHERE action LIKE '%Invalid%'")
    result = cursor.fetchone()
    invalid_signature_count = result['count'] if result else 0
    
    is_valid, corrupted_index = healthchain_blockchain.is_chain_valid()
    blockchain_valid = is_valid
    
    security_alert = (tampering_count > 0 or invalid_signature_count > 0 or not blockchain_valid)
    
    cursor.close()
    conn.close()
    
    return render_template('admin_dashboard.html',
                          username=admin_username,
                          total_users=total_users,
                          total_patients=total_patients,
                          total_doctors=total_doctors,
                          total_records=total_records,
                          total_activity_logs=total_activity_logs,
                          total_blocks=total_blocks,
                          security_alert=security_alert)


# ---------------- UPLOAD RECORD ----------------

@app.route('/upload_record_page', methods=['GET', 'POST'])
def upload_record_page():
    if 'user_id' not in session or session.get('role') != 'doctor':
        return redirect(url_for('login'))

    if request.method == 'POST':
        patient_username = request.form.get('patient_username', '').strip()
        diagnosis = request.form.get('diagnosis', '').strip()
        prescription = request.form.get('prescription', '').strip()

        if not patient_username or not diagnosis or not prescription:
            flash('All fields required')
            return render_template('upload_record.html')

        doctor_username = session.get('username')

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            "SELECT * FROM users WHERE username=%s AND role='patient'",
            (patient_username,)
        )
        patient = cursor.fetchone()

        if not patient:
            flash("Patient not found")
            cursor.close()
            conn.close()
            return render_template('upload_record.html')

        cursor.execute(
            """SELECT * FROM access_requests 
               WHERE doctor_username=%s 
               AND patient_username=%s 
               AND status='Approved'""",
            (doctor_username, patient_username)
        )
        approved_access = cursor.fetchone()

        if not approved_access:
            flash("Access not granted by patient")
            cursor.close()
            conn.close()
            return render_template('upload_record.html')

        patient_encryption_key = patient['encryption_key']
        if patient_encryption_key:
            cipher = Fernet(decrypt_data(patient_encryption_key).encode())
            encrypted_diagnosis = cipher.encrypt(diagnosis.encode()).decode()
            encrypted_prescription = cipher.encrypt(prescription.encode()).decode()
        else:
            encrypted_diagnosis = diagnosis
            encrypted_prescription = prescription
        
        cursor.execute("""
            INSERT INTO records (patient_username, doctor_username, diagnosis, prescription)
            VALUES (%s,%s,%s,%s)
        """, (patient_username, doctor_username, encrypted_diagnosis, encrypted_prescription))

        record_id = cursor.lastrowid
        conn.commit()
        cursor.close()
        conn.close()

        record_data = patient_username + doctor_username + diagnosis + prescription
        hash_obj = SHA256.new(record_data.encode())

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT private_key FROM users WHERE username=%s", (doctor_username,))
        doctor = cursor.fetchone()
        cursor.close()
        conn.close()

        private_key_str = decrypt_data(doctor['private_key']) if doctor and doctor['private_key'] else None
        if not private_key_str:
            flash("Your account has no signing key. Please contact the administrator.")
            return render_template('upload_record.html')
        private_key = RSA.import_key(private_key_str)

        signature = pkcs1_15.new(private_key).sign(hash_obj)
        signature_encoded = base64.b64encode(signature).decode()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE records SET signature=%s WHERE id=%s",
            (signature_encoded, record_id)
        )
        conn.commit()
        cursor.close()
        conn.close()

        record_hash = hashlib.sha256(record_data.encode()).hexdigest()
        
        # Smart Contract Validation - Validate before creating block
        validation_result = validate_medical_record({
            'patient_username': patient_username,
            'doctor_username': doctor_username,
            'diagnosis': diagnosis,
            'prescription': prescription,
            'signature': signature_encoded,
            'record_hash': record_hash
        })
        
        if not validation_result['valid']:
            flash(validation_result['message'])
            return render_template('upload_record.html')
        
        # Validation passed - create block
        healthchain_blockchain.add_block(record_hash)

        log_activity(doctor_username, "Record Uploaded")

        flash("Record uploaded successfully with digital signature!")
        return redirect(url_for('doctor_dashboard'))

    return render_template('upload_record.html')


# ---------------- SMART CONTRACT VALIDATION LAYER ----------------

def validate_medical_record(data):
    """
    Smart contract validation function for medical records.
    Validates all requirements before allowing block creation.
    
    Args:
        data: Dictionary containing patient_username, doctor_username, diagnosis, 
              prescription, signature, record_hash
    
    Returns:
        Dictionary with 'valid' (bool) and 'message' (str) keys
    """
    try:
        # Rule 1: patient_id must exist in database
        patient_username = data.get('patient_username')
        if not patient_username:
            return {'valid': False, 'message': 'Smart contract validation failed: Patient ID is required'}
        
        conn = get_db_connection()
        if not conn:
            return {'valid': False, 'message': 'Smart contract validation failed: Database connection error'}
        
        cursor = conn.cursor(dictionary=True)
        
        # Check patient exists
        cursor.execute("SELECT * FROM users WHERE username = %s AND role = 'patient'", (patient_username,))
        patient = cursor.fetchone()
        
        if not patient:
            cursor.close()
            conn.close()
            return {'valid': False, 'message': 'Smart contract validation failed: Patient not found'}
        
        # Rule 2: doctor_id must exist and role must be "doctor"
        doctor_username = data.get('doctor_username')
        if not doctor_username:
            cursor.close()
            conn.close()
            return {'valid': False, 'message': 'Smart contract validation failed: Doctor ID is required'}
        
        cursor.execute("SELECT * FROM users WHERE username = %s AND role = 'doctor'", (doctor_username,))
        doctor = cursor.fetchone()
        
        if not doctor:
            cursor.close()
            conn.close()
            return {'valid': False, 'message': 'Smart contract validation failed: Doctor not found or invalid role'}
        
        # Rule 3: Record data must not be empty
        diagnosis = data.get('diagnosis', '').strip()
        prescription = data.get('prescription', '').strip()
        
        if not diagnosis or not prescription:
            cursor.close()
            conn.close()
            return {'valid': False, 'message': 'Smart contract validation failed: Record data must not be empty'}
        
        # Rule 4: Digital signature must be present
        signature = data.get('signature')
        if not signature:
            cursor.close()
            conn.close()
            return {'valid': False, 'message': 'Smart contract validation failed: Digital signature is required'}
        
        # Rule 5: record_hash must not already exist in blockchain
        record_hash = data.get('record_hash')
        if not record_hash:
            cursor.close()
            conn.close()
            return {'valid': False, 'message': 'Smart contract validation failed: Record hash is required'}
        
        # Check if record_hash already exists in blockchain
        for block in healthchain_blockchain.chain:
            if block.record_hash == record_hash:
                cursor.close()
                conn.close()
                return {'valid': False, 'message': 'Smart contract validation failed: Record already exists in blockchain'}
        
        cursor.close()
        conn.close()
        
        # All validations passed
        return {'valid': True, 'message': 'Validation successful'}
        
    except Exception as e:
        print(f"Smart contract validation error: {str(e)}")
        return {'valid': False, 'message': 'Smart contract validation failed: internal error'}


# ---------------- VIEW RECORDS (Patient) ----------------

@app.route('/view_records')
def view_records():
    if 'user_id' not in session or session.get('role') != 'patient':
        return redirect(url_for('login'))
    
    patient_username = session.get('username')
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM records WHERE patient_username = %s ORDER BY created_at DESC",
        (patient_username,)
    )
    records = cursor.fetchall()
    
    cursor.execute("SELECT encryption_key FROM users WHERE username = %s", (patient_username,))
    patient_info = cursor.fetchone()
    patient_key = patient_info['encryption_key'] if patient_info else None
    
    if patient_key:
        cipher = Fernet(decrypt_data(patient_key).encode())
        for record in records:
            try:
                record['diagnosis'] = cipher.decrypt(record['diagnosis'].encode()).decode()
                record['prescription'] = cipher.decrypt(record['prescription'].encode()).decode()
            except:
                pass
    cursor.close()
    conn.close()
    
    verified_records = []
    tampering_detected = False
    
    for record in records:
        record_data = (record['patient_username'] + record['doctor_username'] + 
                      record['diagnosis'] + record['prescription'])
        regenerated_hash = hashlib.sha256(record_data.encode()).hexdigest()
        
        is_verified = False
        for block in healthchain_blockchain.chain:
            if block.record_hash == regenerated_hash:
                is_verified = True
                break
        
        record['verified'] = is_verified
        if not is_verified:
            tampering_detected = True
        verified_records.append(record)
    
    if tampering_detected:
        log_activity(patient_username, "Tampering Detected")
    
    return render_template('view_records.html', 
                          username=patient_username, 
                          records=verified_records)


# ---------------- DOWNLOAD RECORD PDF ----------------

@app.route('/download_record/<int:record_id>')
@login_required('patient', 'doctor')
def download_record(record_id):

    try:
        from io import BytesIO
        from flask import send_file
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib import colors
        from reportlab.lib.units import inch

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM records WHERE id = %s", (record_id,))
        record = cursor.fetchone()
        cursor.close()
        conn.close()

        if not record:
            return "Record not found", 404

        # Authorization: the patient who owns the record, or the doctor who wrote it
        # (and who still has approved access). Everyone else gets 403.
        me = session.get('username')
        allowed = False
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        if session.get('role') == 'patient' and record['patient_username'] == me:
            allowed = True
        elif session.get('role') == 'doctor' and record['doctor_username'] == me:
            cursor.execute(
                "SELECT id FROM access_requests WHERE doctor_username=%s AND patient_username=%s AND status='Approved'",
                (me, record['patient_username']))
            allowed = cursor.fetchone() is not None
        cursor.execute("SELECT encryption_key FROM users WHERE username=%s", (record['patient_username'],))
        owner = cursor.fetchone()
        cursor.close()
        conn.close()
        if not allowed:
            log_activity(me, f"Unauthorized download attempt for record {record_id}")
            return "Forbidden", 403

        if owner and owner['encryption_key']:
            try:
                cipher = Fernet(decrypt_data(owner['encryption_key']).encode())
                record['diagnosis'] = cipher.decrypt(record['diagnosis'].encode()).decode()
                record['prescription'] = cipher.decrypt(record['prescription'].encode()).decode()
            except Exception:
                pass

        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer)
        elements = []

        styles = getSampleStyleSheet()
        elements.append(Paragraph("HealthChain Medical Record", styles['Heading1']))
        elements.append(Spacer(1, 0.3 * inch))

        data = [
            ["Patient", record['patient_username']],
            ["Doctor", record['doctor_username']],
            ["Diagnosis", record['diagnosis']],
            ["Prescription", record['prescription']],
            ["Created At", str(record['created_at'])]
        ]

        table = Table(data, colWidths=[120, 350])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica')
        ]))

        elements.append(table)

        doc.build(elements)
        buffer.seek(0)

        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"medical_record_{record_id}.pdf",
            mimetype="application/pdf"
        )

    except Exception as e:
        import traceback
        traceback.print_exc()
        return "Could not generate the PDF.", 500


# ---------------- ACCESS REQUEST (Doctor) ----------------

@app.route('/request_access', methods=['GET', 'POST'])
def request_access():
    if 'user_id' not in session or session.get('role') != 'doctor':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        patient_username = request.form.get('patient_username', '').strip()
        
        if not patient_username:
            flash('Patient username required')
            return render_template('request_access.html')
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # ---- TEMPORARY DEBUG (remove after fixing) ----
        cursor.execute("SELECT DATABASE() AS db, @@hostname AS host, @@port AS port")
        print("FLASK IS USING:", cursor.fetchone(), "| searching for:", repr(patient_username))
        cursor.execute("SELECT username, role FROM users")
        print("USERS FLASK SEES:", cursor.fetchall())
        # ---- END DEBUG ----

        cursor.execute(
            "SELECT * FROM users WHERE username=%s AND role='patient'",
            (patient_username,)
        )
        patient = cursor.fetchone()

        if not patient:
            flash("Patient not found")
            cursor.close()
            conn.close()
            return render_template('request_access.html')
        
        doctor_username = session.get('username')
        
        cursor.execute(
            "SELECT * FROM access_requests WHERE doctor_username=%s AND patient_username=%s",
            (doctor_username, patient_username)
        )
        existing_request = cursor.fetchone()
        
        if existing_request:
            flash("Access request already exists")
            cursor.close()
            conn.close()
            return render_template('request_access.html')
        
        cursor.execute(
            "INSERT INTO access_requests (doctor_username, patient_username, status) VALUES (%s, %s, 'Pending')",
            (doctor_username, patient_username)
        )
        
        conn.commit()
        cursor.close()
        conn.close()
        
        log_activity(doctor_username, f"Requested access to patient {patient_username}")
        
        flash("Access request sent to patient")
        return redirect(url_for('doctor_dashboard'))
    
    return render_template('request_access.html')


# ---------------- MANAGE REQUESTS (Patient) ----------------

@app.route('/manage_requests')
def manage_requests():
    if 'user_id' not in session or session.get('role') != 'patient':
        return redirect(url_for('login'))
    
    patient_username = session.get('username')
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM access_requests WHERE patient_username = %s ORDER BY created_at DESC",
        (patient_username,)
    )
    requests = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template('manage_requests.html', username=patient_username, requests=requests)


@app.route('/handle_request', methods=['POST'])
def handle_request():
    if 'user_id' not in session or session.get('role') != 'patient':
        return redirect(url_for('login'))
    
    request_id = request.form.get('request_id', '')
    action = request.form.get('action')
    
    if not request_id.isdigit() or not action:
        flash('Invalid request')
        return redirect(url_for('manage_requests'))
    
    if action not in ['Approved', 'Rejected']:
        flash('Invalid action')
        return redirect(url_for('manage_requests'))
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    patient_username = session.get('username')

    # Only the patient the request is addressed to may answer it (prevents IDOR)
    cursor.execute(
        "SELECT * FROM access_requests WHERE id = %s AND patient_username = %s",
        (request_id, patient_username)
    )
    request_details = cursor.fetchone()

    if request_details:
        cursor.execute(
            "UPDATE access_requests SET status = %s WHERE id = %s AND patient_username = %s",
            (action, request_id, patient_username)
        )
        conn.commit()
    cursor.close()
    conn.close()
    
    if not request_details:
        flash('Request not found')
        return redirect(url_for('manage_requests'))

    if request_details:
        log_activity(patient_username, f"{action} access request from Dr. {request_details['doctor_username']}")
    
    flash(f'Request {action}')
    return redirect(url_for('manage_requests'))


# ---------------- BLOCKCHAIN EXPLORER ----------------

@app.route('/blockchain_explorer')
def blockchain_explorer():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    blocks = []
    for block in healthchain_blockchain.chain:
        blocks.append({
            'index': block.index,
            'timestamp': block.timestamp,
            'record_hash': block.record_hash,
            'previous_hash': block.previous_hash,
            'current_hash': block.current_hash
        })
    
    blocks = list(reversed(blocks))
    
    username = session.get('username')
    role = session.get('role')
    
    is_valid, corrupted_index = healthchain_blockchain.is_chain_valid()
    
    return render_template('blockchain_explorer.html', 
                          username=username,
                          role=role,
                          blocks=blocks,
                          is_valid=is_valid,
                          corrupted_index=corrupted_index)


# ---------------- VALIDATE BLOCKCHAIN ----------------

@app.route('/validate_blockchain')
def validate_blockchain():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    admin_username = session.get('username')
    
    is_valid, corrupted_index = healthchain_blockchain.is_chain_valid()
    total_blocks = healthchain_blockchain.get_chain_length()
    
    if is_valid:
        log_activity(admin_username, "Validated blockchain - Integrity Verified")
    else:
        log_activity(admin_username, f"Validated blockchain - COMPROMISED at block {corrupted_index}")
    
    return render_template('validate_blockchain.html',
                          username=admin_username,
                          is_valid=is_valid,
                          corrupted_index=corrupted_index,
                          total_blocks=total_blocks)


# ---------------- SYSTEM INTEGRITY ----------------

@app.route('/system_integrity')
def system_integrity():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    admin_username = session.get('username')
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("""
        SELECT r.id, r.patient_username, r.doctor_username, r.diagnosis, 
               r.prescription, r.signature, r.created_at,
               u.public_key
        FROM records r
        LEFT JOIN users u ON r.doctor_username = u.username
        ORDER BY r.id DESC
    """)
    records = cursor.fetchall()
    
    integrity_results = []
    
    for record in records:
        cursor.execute("SELECT encryption_key FROM users WHERE username = %s", (record['patient_username'],))
        patient_info = cursor.fetchone()
        patient_key = patient_info['encryption_key'] if patient_info else None
        
        diagnosis = record['diagnosis']
        prescription = record['prescription']
        
        if patient_key:
            try:
                cipher = Fernet(decrypt_data(patient_key).encode())
                diagnosis = cipher.decrypt(diagnosis.encode()).decode()
                prescription = cipher.decrypt(prescription.encode()).decode()
            except:
                pass
        
        record_data = (record['patient_username'] + record['doctor_username'] + 
                      diagnosis + prescription)
        regenerated_hash = hashlib.sha256(record_data.encode()).hexdigest()
        
        signature_status = False
        if record['signature'] and record['public_key']:
            try:
                signature_bytes = base64.b64decode(record['signature'])
                hash_obj = SHA256.new(record_data.encode())
                public_key = RSA.import_key(record['public_key'])
                pkcs1_15.new(public_key).verify(hash_obj, signature_bytes)
                signature_status = True
            except:
                signature_status = False
        
        blockchain_status = False
        for block in healthchain_blockchain.chain:
            if block.record_hash == regenerated_hash:
                blockchain_status = True
                break
        
        if signature_status and blockchain_status:
            final_status = "SECURE"
        elif not signature_status and blockchain_status:
            final_status = "DB TAMPERED"
            log_activity(admin_username, "Invalid Signature")
        else:
            final_status = "BLOCKCHAIN COMPROMISED"
        
        integrity_results.append({
            'id': record['id'],
            'signature_status': signature_status,
            'blockchain_status': blockchain_status,
            'final_status': final_status,
            'created_at': record['created_at']
        })
    
    cursor.close()
    conn.close()
    
    secure_count = sum(1 for r in integrity_results if r['final_status'] == 'SECURE')
    db_tampered_count = sum(1 for r in integrity_results if r['final_status'] == 'DB TAMPERED')
    blockchain_compromised_count = sum(1 for r in integrity_results if r['final_status'] == 'BLOCKCHAIN COMPROMISED')
    
    log_activity(admin_username, f"System integrity checked - {secure_count} secure, {db_tampered_count} db tampered, {blockchain_compromised_count} blockchain compromised")
    
    return render_template('system_integrity.html',
                          username=admin_username,
                          records=integrity_results,
                          secure_count=secure_count,
                          db_tampered_count=db_tampered_count,
                          blockchain_compromised_count=blockchain_compromised_count,
                          total_records=len(integrity_results))


# ---------------- RECORD AUDIT TRAIL ----------------

@app.route('/record_audit/<int:record_id>')
def record_audit(record_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    admin_username = session.get('username')
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("""
        SELECT r.*, u.public_key, u.username as doctor_username
        FROM records r
        LEFT JOIN users u ON r.doctor_username = u.username
        WHERE r.id = %s
    """, (record_id,))
    record = cursor.fetchone()
    
    if not record:
        cursor.close()
        conn.close()
        flash('Record not found')
        return redirect(url_for('system_integrity'))
    
    cursor.execute("SELECT encryption_key FROM users WHERE username = %s", (record['patient_username'],))
    patient_info = cursor.fetchone()
    patient_key = patient_info['encryption_key'] if patient_info else None
    
    diagnosis = record['diagnosis']
    prescription = record['prescription']
    
    if patient_key:
        try:
            cipher = Fernet(decrypt_data(patient_key).encode())
            diagnosis = cipher.decrypt(diagnosis.encode()).decode()
            prescription = cipher.decrypt(prescription.encode()).decode()
        except:
            pass
    
    signature_status = False
    signature_message = "Not Verified"
    
    if record['signature'] and record['public_key']:
        try:
            record_data = (record['patient_username'] + record['doctor_username'] + 
                         diagnosis + prescription)
            signature_bytes = base64.b64decode(record['signature'])
            hash_obj = SHA256.new(record_data.encode())
            public_key = RSA.import_key(record['public_key'])
            pkcs1_15.new(public_key).verify(hash_obj, signature_bytes)
            signature_status = True
            signature_message = "Valid"
        except:
            signature_status = False
            signature_message = "Invalid - Signature verification failed"
    else:
        signature_message = "No signature found"
    
    record_data = (record['patient_username'] + record['doctor_username'] + 
                  diagnosis + prescription)
    regenerated_hash = hashlib.sha256(record_data.encode()).hexdigest()
    
    blockchain_status = False
    blockchain_message = "Not Found in Blockchain"
    
    for block in healthchain_blockchain.chain:
        if block.record_hash == regenerated_hash:
            blockchain_status = True
            blockchain_message = "Verified in Blockchain"
            break
    
    cursor.execute("""
        SELECT * FROM activity_logs 
        WHERE action LIKE '%Tamper%' OR action LIKE '%Invalid%' OR action LIKE '%Signature%'
        ORDER BY timestamp DESC
        LIMIT 10
    """)
    tampering_logs = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('record_audit.html',
                          username=admin_username,
                          record=record,
                          diagnosis=diagnosis,
                          prescription=prescription,
                          signature_status=signature_status,
                          signature_message=signature_message,
                          blockchain_status=blockchain_status,
                          blockchain_message=blockchain_message,
                          tampering_logs=tampering_logs)


# ---------------- SECURITY DASHBOARD ----------------

@app.route('/security_dashboard')
def security_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    admin_username = session.get('username')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT COUNT(*) as count FROM activity_logs WHERE action LIKE '%Tamper%'")
    result = cursor.fetchone()
    tampering_count = result['count'] if result else 0

    cursor.execute("SELECT COUNT(*) as count FROM activity_logs WHERE action LIKE '%Invalid%'")
    result = cursor.fetchone()
    invalid_signature_count = result['count'] if result else 0

    cursor.execute("""
        SELECT doctor_username, COUNT(*) as count 
        FROM records
        GROUP BY doctor_username
        ORDER BY COUNT(*) DESC
        LIMIT 1
    """)
    most_active_doctor = cursor.fetchone()
    if most_active_doctor is None:
        most_active_doctor = {'doctor_username': 'No Data', 'count': 0}

    cursor.execute("""
        SELECT patient_username, COUNT(*) as count
        FROM access_requests
        GROUP BY patient_username
        ORDER BY COUNT(*) DESC
        LIMIT 1
    """)
    most_requested_patient = cursor.fetchone()
    if most_requested_patient is None:
        most_requested_patient = {'patient_username': 'No Data', 'count': 0}

    cursor.close()
    conn.close()

    return render_template('security_dashboard.html',
                          username=admin_username,
                          tampering_count=tampering_count,
                          invalid_signature_count=invalid_signature_count,
                          most_active_doctor=most_active_doctor,
                          most_requested_patient=most_requested_patient)


# ---------------- ACTIVITY LOGS ----------------

@app.route('/activity_logs')
def activity_logs():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    username = session.get('username')
    role = session.get('role')
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT * FROM activity_logs 
        ORDER BY timestamp DESC 
        LIMIT 20
    """)
    activities = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template('activity_logs.html', 
                          username=username,
                          role=role,
                          activities=activities)


# ---------------- STARTUP BLOCKCHAIN VALIDATION ----------------

def validate_blockchain_on_startup():
    """Validate blockchain on application startup."""
    is_valid, corrupted_index = healthchain_blockchain.is_chain_valid()
    if not is_valid:
        print(f"\n{'='*60}")
        print("⚠️  WARNING: Blockchain integrity issue detected!")
        print(f"   Corrupted block index: {corrupted_index}")
        print("   Please investigate immediately.")
        print(f"{'='*60}\n")
    else:
        print(f"\n{'='*60}")
        print("✅ Blockchain integrity verified on startup")
        print(f"   Total blocks: {healthchain_blockchain.get_chain_length()}")
        print(f"{'='*60}\n")


# ---------------- ADD PEER NODE ----------------

@app.route('/add_peer', methods=['GET', 'POST'])
@login_required('admin')
def add_peer():
    if request.method == 'POST':
        peer_url = (request.form.get('peer_url') or '').strip().rstrip('/')

        if not is_valid_peer_url(peer_url):
            flash('Invalid peer URL. Use the form http://host:port')
        else:
            healthchain_blockchain.peer_nodes.add(peer_url)
            log_activity(session.get('username'), f"Added peer node {peer_url}")
            flash(f'Peer {peer_url} added successfully')
        return redirect(url_for('add_peer'))

    from markupsafe import escape
    from flask import get_flashed_messages
    from security import generate_csrf_token
    msgs = ''.join(f'<p>{escape(m)}</p>' for m in get_flashed_messages())
    return f'''
    <h2>Add Peer Node</h2>
    {msgs}
    <form method="post">
        <input type="hidden" name="csrf_token" value="{generate_csrf_token()}">
        <input type="text" name="peer_url" placeholder="http://127.0.0.1:5001" required>
        <button type="submit">Add Peer</button>
    </form>
    <p><a href="{url_for('admin_dashboard')}">Back</a></p>
    '''
@app.route('/get_chain')
def get_chain():
    return jsonify({'chain': healthchain_blockchain.get_chain_data(), 'length': healthchain_blockchain.get_chain_length()})

@app.route('/receive_block', methods=['POST'])
def receive_block():
    """Receive a block from a peer node and add it to the chain.
    Requires the shared PEER_TOKEN header; otherwise anyone could append blocks."""
    if not peer_token_valid():
        return jsonify({'error': 'Unauthorized peer'}), 403
    import logging
    logger = logging.getLogger(__name__)
    
    data = request.get_json()
    if not data:
        logger.warning("receive_block: No data provided in request")
        return jsonify({'error': 'No data'}), 400
    
    logger.info(f"receive_block: Received block {data.get('index')} from {request.remote_addr}")
    logger.debug(f"receive_block: Block data - {data}")
    
    # FIXED: First resolve conflicts to ensure we have the latest chain
    logger.info("receive_block: Attempting conflict resolution first...")
    replaced = healthchain_blockchain.resolve_conflicts()
    if replaced:
        logger.info(f"receive_block: Chain was replaced. New length: {healthchain_blockchain.get_chain_length()}")
        return jsonify({
            'message': 'Chain replaced', 
            'length': healthchain_blockchain.get_chain_length(),
            'action': 'chain_replaced'
        })
    
    # Now try to add the received block
    logger.info(f"receive_block: Attempting to add block {data.get('index')} to chain")
    success = healthchain_blockchain.add_received_block(data)
    
    if success:
        logger.info(f"receive_block: Block {data.get('index')} successfully added. Chain length: {healthchain_blockchain.get_chain_length()}")
        return jsonify({
            'message': 'Block added',
            'block_index': data.get('index'),
            'chain_length': healthchain_blockchain.get_chain_length()
        })
    
    # If block addition failed, try conflict resolution again (chain might have gaps)
    logger.warning(f"receive_block: Block {data.get('index')} validation failed - attempting conflict resolution")
    replaced = healthchain_blockchain.resolve_conflicts()
    if replaced:
        logger.info(f"receive_block: Chain replaced after failed block add. New length: {healthchain_blockchain.get_chain_length()}")
        return jsonify({
            'message': 'Chain replaced', 
            'length': healthchain_blockchain.get_chain_length(),
            'action': 'chain_replaced_after_failure'
        })
    
    logger.error(f"receive_block: Block {data.get('index')} validation failed - rejecting block")
    return jsonify({'error': 'Validation failed'}), 400

@app.route('/resolve_conflicts', methods=['POST'])
@login_required('admin')
def resolve_conflicts():
    replaced = healthchain_blockchain.resolve_conflicts()
    return jsonify({'replaced': replaced, 'length': healthchain_blockchain.get_chain_length()})


# ---------------- DEV ROUTES ----------------

@app.route('/dev/reset_chain', methods=['POST'])
@login_required('admin')
def dev_reset_chain():
    """
    Development-only route to reset the blockchain.
    Deletes blockchain_data.json and reinitializes with a fresh genesis block.
    """
    if os.getenv('ENABLE_DEV_ROUTES', 'false').lower() not in ('1', 'true', 'yes'):
        return jsonify({"error": "Disabled. Set ENABLE_DEV_ROUTES=true to enable."}), 403
    try:
        # Delete the blockchain data file if it exists
        if os.path.exists('blockchain_data.json'):
            os.remove('blockchain_data.json')
        
        # Reinitialize blockchain with fresh genesis block
        healthchain_blockchain.chain = []
        healthchain_blockchain.create_genesis_block()
        healthchain_blockchain.save()
        
        return jsonify({
            "message": "Blockchain reset successful",
            "chain_length": 1
        })
    except Exception as e:
        return jsonify({"error": 'Internal server error'}), 500


# ---------------- PEER NETWORKING ENDPOINTS (Multi-Node Support) ----------------

@app.route('/resolve', methods=['GET'])
@login_required('admin')
def resolve_conflicts_public():
    """
    Public endpoint for peer-to-peer conflict resolution.
    Uses longest chain rule - replaces local chain if a longer valid chain is found.
    Accessible without authentication for peer node communication.
    """
    replaced = healthchain_blockchain.resolve_conflicts()
    return jsonify({
        'replaced': replaced,
        'new_length': healthchain_blockchain.get_chain_length(),
        'message': 'Chain replaced with longer valid chain' if replaced else 'No longer chain found - current chain is authoritative'
    })


@app.route('/get_peers', methods=['GET'])
@login_required('admin')
def get_peers():
    """
    Get list of registered peer nodes.
    Accessible without authentication for peer discovery.
    """
    peers = list(healthchain_blockchain.peer_nodes)
    return jsonify({
        'peers': peers,
        'count': len(peers),
        'node_id': healthchain_blockchain.node_id
    })


# ---------------- ETHEREUM ANCHORING ----------------

@app.route('/eth_status', methods=['GET'])
@login_required()
def eth_status():
    try:
        info = ethereum_anchor.get_network_info()
        return jsonify(info)
    except Exception as e:
        return jsonify({
            "connected": False,
            "error": 'Internal server error',
            "network": None,
            "latest_block": None
        }), 500


@app.route('/verify_block/<int:index>')
@login_required()
def verify_block(index):
    from blockchain import healthchain_blockchain

    if index >= len(healthchain_blockchain.chain):
        return jsonify({"error": "Invalid block index"}), 400

    block = healthchain_blockchain.chain[index]

    if not block.ethereum_tx_hash:
        return jsonify({"verified": False, "reason": "Not anchored to Ethereum"})

    result = ethereum_anchor.verify_transaction(block.ethereum_tx_hash)
    return jsonify(result)


# ---------------- PHASE 22 - ETHEREUM UI INTEGRATION ----------------

@app.route('/doctor_dashboard_ethereum')
def doctor_dashboard_ethereum():
    """PHASE 22: Enhanced doctor dashboard with Ethereum anchoring status"""
    if 'user_id' not in session or session.get('role') != 'doctor':
        return redirect(url_for('login'))

    doctor_username = session.get('username')
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT COUNT(*) as count FROM users WHERE role='patient'")
    total_patients = cursor.fetchone()['count']
    
    cursor.execute("SELECT COUNT(*) as count FROM records WHERE doctor_username=%s", (doctor_username,))
    total_records = cursor.fetchone()['count']
    
    cursor.execute("SELECT COUNT(*) as count FROM access_requests WHERE doctor_username=%s AND status='Approved'", (doctor_username,))
    approved_requests = cursor.fetchone()['count']
    
    cursor.execute("""
        SELECT r.id, r.patient_username, r.diagnosis, r.prescription, r.created_at
        FROM records r
        WHERE r.doctor_username = %s
        ORDER BY r.created_at DESC
        LIMIT 10
    """, (doctor_username,))
    recent_records = cursor.fetchall()
    
    blocks_info = []
    for block in healthchain_blockchain.chain:
        blocks_info.append({
            'index': block.index,
            'ethereum_tx_hash': block.ethereum_tx_hash,
            'record_hash': block.record_hash
        })
    
    anchored_count = sum(1 for b in blocks_info if b.get('ethereum_tx_hash'))
    
    for record in recent_records:
        cursor.execute("SELECT encryption_key FROM users WHERE username = %s", (record['patient_username'],))
        patient_info = cursor.fetchone()
        if patient_info and patient_info['encryption_key']:
            try:
                cipher = Fernet(decrypt_data(patient_info['encryption_key']).encode())
                record['diagnosis'] = cipher.decrypt(record['diagnosis'].encode()).decode()
                record['prescription'] = cipher.decrypt(record['prescription'].encode()).decode()
            except:
                pass
    
    cursor.close()
    conn.close()
    
    try:
        eth_status = ethereum_anchor.get_network_info()
    except:
        eth_status = {"connected": False, "network": None, "latest_block": None}
    
    return render_template('doctor_dashboard.html', 
                          username=doctor_username,
                          total_patients=total_patients,
                          total_records=total_records,
                          approved_requests=approved_requests,
                          recent_records=recent_records,
                          eth_status=eth_status,
                          anchored_blocks=anchored_count,
                          blocks_info=blocks_info)


# ---------------- PHASE 23 - ADMIN MONITORING DASHBOARD ----------------

@app.route('/admin_monitor')
def admin_monitor():
    """PHASE 23: Admin monitoring dashboard with system status"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    admin_username = session.get('username')
    
    chain_length = healthchain_blockchain.get_chain_length()
    is_valid, corrupted_index = healthchain_blockchain.is_chain_valid()
    
    peer_count = len(healthchain_blockchain.peer_nodes)
    peers = list(healthchain_blockchain.peer_nodes)
    
    try:
        eth_status = ethereum_anchor.get_network_info()
    except Exception as e:
        eth_status = {"connected": False, "error": 'Internal server error', "network": None, "latest_block": None}
    
    anchored_blocks = 0
    for block in healthchain_blockchain.chain:
        if block.ethereum_tx_hash:
            anchored_blocks += 1
    
    node_health = "Healthy" if is_valid else "Compromised"
    
    return render_template('admin_monitor.html',
                          username=admin_username,
                          chain_length=chain_length,
                          peer_count=peer_count,
                          peers=peers,
                          node_health=node_health,
                          eth_connected=eth_status.get('connected', False),
                          eth_network=eth_status.get('network'),
                          eth_latest_block=eth_status.get('latest_block'),
                          anchored_blocks=anchored_blocks,
                          is_valid=is_valid,
                          corrupted_index=corrupted_index)


# ---------------- REST API LAYER (Blockchain Access) ----------------

@app.route('/api/chain', methods=['GET'])
def api_get_chain():
    """
    Get the full blockchain as JSON.
    Returns all blocks with their complete data.
    """
    try:
        chain_data = healthchain_blockchain.get_chain_data()
        return jsonify({
            'success': True,
            'chain': chain_data,
            'length': len(chain_data),
            'node_id': healthchain_blockchain.node_id
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@app.route('/api/block/<int:block_index>', methods=['GET'])
def api_get_block(block_index):
    """
    Get a specific block by index.
    Returns block data if found, or error if not found.
    """
    try:
        chain = healthchain_blockchain.chain
        
        # Check if block index is valid
        if block_index < 0 or block_index >= len(chain):
            return jsonify({
                'success': False,
                'error': 'Block not found',
                'message': f'Block index {block_index} is out of range. Valid range: 0-{len(chain)-1}'
            }), 404
        
        block = chain[block_index]
        return jsonify({
            'success': True,
            'block': {
                'index': block.index,
                'timestamp': block.timestamp.isoformat(),
                'record_hash': block.record_hash,
                'previous_hash': block.previous_hash,
                'current_hash': block.current_hash
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@app.route('/api/health', methods=['GET'])
def api_health():
    """
    Get node health status.
    Returns running status and chain information.
    """
    try:
        is_valid, corrupted_index = healthchain_blockchain.is_chain_valid()
        
        return jsonify({
            'success': True,
            'status': 'running',
            'healthy': is_valid,
            'chain_length': healthchain_blockchain.get_chain_length(),
            'total_blocks': healthchain_blockchain.get_chain_length(),
            'integrity': {
                'is_valid': is_valid,
                'corrupted_index': corrupted_index
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'status': 'error',
            'error': 'Internal server error'
        }), 500


@app.route('/api/info', methods=['GET'])
@login_required('admin')
def api_info():
    """
    Get node metadata information.
    Returns node configuration and network information.
    """
    try:
        import sys
        
        # Get current port from command line args (default 5000)
        port = 5000
        if len(sys.argv) > 1:
            try:
                port = int(sys.argv[2])
            except:
                pass
        
        return jsonify({
            'success': True,
            'node_id': healthchain_blockchain.node_id,
            'port': port,
            'peer_count': len(healthchain_blockchain.peer_nodes),
            'peers': list(healthchain_blockchain.peer_nodes),
            'chain_length': healthchain_blockchain.get_chain_length(),
            'blockchain_file': 'blockchain_data.json',
            'version': '1.0.0'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500

# ---------------- RUN ----------------
import sys

if __name__ == '__main__':
    init_database()
    validate_blockchain_on_startup()

    port = 5000  # default

    # Usage: python app.py [port]   (also accepts: python app.py --port 5001)
    for arg in sys.argv[1:]:
        if arg.isdigit():
            port = int(arg)

    # Start automatic chain synchronization with peers in background thread
    # This runs without blocking the Flask server startup
    import threading
    sync_thread = threading.Thread(target=healthchain_blockchain.sync_with_peers_on_startup)
    sync_thread.daemon = True  # Thread will not prevent app from exiting
    sync_thread.start()
    
    # Bind to localhost by default. For a real deployment run behind a HTTPS reverse
    # proxy (nginx/Caddy) or a WSGI server (waitress/gunicorn) - see README.
    host = os.getenv('HOST', '127.0.0.1')
    app.run(host=host, port=port, debug=False)