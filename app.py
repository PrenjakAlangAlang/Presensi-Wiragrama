from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
# Remove these imports
# from werkzeug.security import generate_password_hash, check_password_hash
from db import get_connection

app = Flask(__name__)
app.secret_key = 'secret-key-yang-sangat-aman'

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, role, nama_lengkap):
        self.id = id
        self.username = username
        self.role = role
        self.nama_lengkap = nama_lengkap

@login_manager.user_loader
def load_user(user_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, username, role, nama_lengkap FROM users WHERE id = %s", (user_id,))
    user_data = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if user_data:
        return User(id=user_data['id'], username=user_data['username'], 
                   role=user_data['role'], nama_lengkap=user_data['nama_lengkap'])
    return None

# Auth Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username dan password diperlukan', 'danger')
            return redirect(url_for('login'))

        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)
            
            print(f"Searching for user: {username}")
            cursor.execute(
                "SELECT id, username, password, role, nama_lengkap FROM users WHERE username = %s", 
                (username,)
            )
            user_data = cursor.fetchone()
            print(f"User data: {user_data}")
            
            if user_data:
                print(f"Stored password: {user_data['password']}")
                
                # Direct password comparison
                if user_data['password'] == password:
                    user = User(
                        id=user_data['id'],
                        username=user_data['username'],
                        role=user_data['role'],
                        nama_lengkap=user_data['nama_lengkap']
                    )
                    login_user(user)
                    print(f"User {username} logged in successfully")
                    flash('Login berhasil!', 'success')
                    return redirect(url_for('home'))
                else:
                    print("Password mismatch")
            else:
                print("User not found")
            
            flash('Username atau password salah', 'danger')
            
        except Exception as e:
            print(f"Error during login: {str(e)}")
            flash('Terjadi kesalahan sistem', 'danger')
            
        finally:
            if 'cursor' in locals(): cursor.close()
            if 'conn' in locals(): conn.close()
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Anda telah logout.', 'info')
    return redirect(url_for('login'))

@app.route('/')
def home():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('anggota_dashboard'))
    return redirect(url_for('login'))

# Admin Routes
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return jsonify({"message": "Unauthorized"}), 403
    
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT COUNT(*) as total FROM users WHERE role = 'anggota'")
    total_anggota = cursor.fetchone()['total']
    
    cursor.execute("SELECT COUNT(*) as total FROM presensi WHERE DATE(waktu_presensi) = CURDATE()")
    total_presensi = cursor.fetchone()['total']
    
    # Updated query to match kas_report - count both "masuk" and "tidak hadir" status
    cursor.execute("""
        SELECT COUNT(*) as total 
        FROM presensi 
        WHERE kas_paid = TRUE AND (status = 'masuk' OR status = 'tidak hadir')
    """)
    total_kas = cursor.fetchone()['total'] * 5000 + 2434500 # Rp 5000 per entry
    
    cursor.execute("""
        SELECT u.nama_lengkap, p.waktu_presensi, p.status 
        FROM presensi p
        JOIN users u ON p.user_id = u.id
        ORDER BY p.waktu_presensi DESC
        LIMIT 5
    """)
    presensi_terbaru = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('admin/dashboard.html', 
                         total_anggota=total_anggota,
                         total_presensi=total_presensi,
                         total_kas=total_kas,
                         presensi_terbaru=presensi_terbaru)

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if current_user.role != 'admin':
        return jsonify({"message": "Unauthorized"}), 403
    
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    
    if request.method == 'POST':
        nama_lengkap = request.form['nama_lengkap']
        username = request.form['username']
        password = request.form['password']  # Store password directly
        role = request.form['role']
        
        try:
            cursor.execute("""
                INSERT INTO users (nama_lengkap, username, password, role)
                VALUES (%s, %s, %s, %s)
            """, (nama_lengkap, username, password, role))
            conn.commit()
            flash('User berhasil ditambahkan!', 'success')
        except Exception as e:
            conn.rollback()
            flash(f'Error: {str(e)}', 'danger')
    
    cursor.execute("SELECT id, username, role, nama_lengkap FROM users ORDER BY id DESC")
    users = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template('admin/manage_users.html', users=users)

@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        flash('Anda tidak memiliki akses', 'danger')
        return redirect(url_for('home'))
    
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    
    # GET request - display form with user data
    if request.method == 'GET':
        cursor.execute("SELECT id, username, nama_lengkap, role FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        
        if not user:
            flash('User tidak ditemukan', 'danger')
            return redirect(url_for('manage_users'))
            
        cursor.close()
        conn.close()
        
        return render_template('admin/edit_user.html', user=user)
    
    # POST request - update user data
    elif request.method == 'POST':
        nama_lengkap = request.form.get('nama_lengkap')
        username = request.form.get('username')
        role = request.form.get('role')
        password = request.form.get('password')
        
        try:
            # Check if username already exists (excluding current user)
            cursor.execute("SELECT id FROM users WHERE username = %s AND id != %s", (username, user_id))
            if cursor.fetchone():
                flash('Username sudah digunakan', 'danger')
                return redirect(url_for('edit_user', user_id=user_id))
            
            # If password is provided, update it too
            if password:
                cursor.execute("""
                    UPDATE users 
                    SET nama_lengkap = %s, username = %s, role = %s, password = %s
                    WHERE id = %s
                """, (nama_lengkap, username, role, password, user_id))
            else:
                cursor.execute("""
                    UPDATE users 
                    SET nama_lengkap = %s, username = %s, role = %s
                    WHERE id = %s
                """, (nama_lengkap, username, role, user_id))
                
            conn.commit()
            flash('User berhasil diperbarui', 'success')
            
        except Exception as e:
            conn.rollback()
            flash(f'Error: {str(e)}', 'danger')
            
        finally:
            cursor.close()
            conn.close()
            
        return redirect(url_for('manage_users'))

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('Anda tidak memiliki akses', 'danger')
        return redirect(url_for('home'))
    
    # Don't allow deleting yourself
    if int(user_id) == int(current_user.id):
        flash('Anda tidak dapat menghapus akun sendiri', 'danger')
        return redirect(url_for('manage_users'))
    
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        # Delete user's attendance records first (to maintain referential integrity)
        cursor.execute("DELETE FROM presensi WHERE user_id = %s", (user_id,))
        
        # Then delete the user
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        
        conn.commit()
        flash('User berhasil dihapus', 'success')
        
    except Exception as e:
        conn.rollback()
        flash(f'Error: {str(e)}', 'danger')
        
    finally:
        cursor.close()
        conn.close()
        
    return redirect(url_for('manage_users'))

# Add these routes after your existing admin routes

@app.route('/admin/sesi', methods=['GET'])
@login_required
def manage_sesi():
    if current_user.role != 'admin':
        flash('Anda tidak memiliki akses', 'danger')
        return redirect(url_for('home'))
    
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Get all sessions with kas data
    cursor.execute("""
        SELECT s.*, u.nama_lengkap as admin_name,
        (SELECT COUNT(*) FROM presensi WHERE sesi_id = s.id) as total_presensi,
        (SELECT COUNT(*) FROM presensi WHERE sesi_id = s.id AND kas_paid = TRUE) as total_kas_paid
        FROM presensi_sesi s
        JOIN users u ON s.created_by = u.id
        ORDER BY s.tanggal DESC, s.created_at DESC
    """)
    sesi_list = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('admin/manage_sesi.html', sesi_list=sesi_list)

@app.route('/admin/sesi/new', methods=['GET', 'POST'])
@login_required
def create_sesi():
    if current_user.role != 'admin':
        flash('Anda tidak memiliki akses', 'danger')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        judul = request.form.get('judul')
        tanggal = request.form.get('tanggal')
        # Hapus jam_mulai dan jam_selesai
        
        conn = get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO presensi_sesi (judul, tanggal, created_by)
                VALUES (%s, %s, %s)
            """, (judul, tanggal, current_user.id))
            
            conn.commit()
            flash('Sesi presensi berhasil dibuat', 'success')
            return redirect(url_for('manage_sesi'))
            
        except Exception as e:
            conn.rollback()
            flash(f'Error: {str(e)}', 'danger')
            
        finally:
            cursor.close()
            conn.close()
    
    return render_template('admin/create_sesi.html')

@app.route('/admin/sesi/<int:sesi_id>/detail', methods=['GET'])
@login_required
def sesi_detail(sesi_id):
    if current_user.role != 'admin':
        flash('Anda tidak memiliki akses', 'danger')
        return redirect(url_for('home'))
    
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Get session info
    cursor.execute("SELECT * FROM presensi_sesi WHERE id = %s", (sesi_id,))
    sesi = cursor.fetchone()
    
    if not sesi:
        flash('Sesi tidak ditemukan', 'danger')
        return redirect(url_for('manage_sesi'))
    
    # Get attendance for this session including kas_paid status
    cursor.execute("""
        SELECT p.*, u.nama_lengkap
        FROM presensi p
        JOIN users u ON p.user_id = u.id
        WHERE p.sesi_id = %s
        ORDER BY p.waktu_presensi DESC
    """, (sesi_id,))
    presensi_list = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('admin/sesi_detail.html', sesi=sesi, presensi_list=presensi_list)

@app.route('/admin/sesi/<int:sesi_id>/close', methods=['POST'])
@login_required
def close_sesi(sesi_id):
    if current_user.role != 'admin':
        flash('Anda tidak memiliki akses', 'danger')
        return redirect(url_for('home'))
    
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Get all anggota users
        cursor.execute("SELECT id FROM users WHERE role = 'anggota'")
        all_users = cursor.fetchall()
        
        # For each user, check if they have attended
        for user in all_users:
            user_id = user['id']
            
            # Check if user has already checked in for this session
            cursor.execute("""
                SELECT COUNT(*) as attended FROM presensi
                WHERE user_id = %s AND sesi_id = %s AND status = 'masuk'
            """, (user_id, sesi_id))
            
            # If user hasn't checked in, mark them as absent
            if cursor.fetchone()['attended'] == 0:
                # Insert absence record with "tidak hadir" status
                cursor.execute("""
                    INSERT INTO presensi (user_id, status, sesi_id, kas_paid, is_absent)
                    VALUES (%s, 'tidak hadir', %s, FALSE, TRUE)
                """, (user_id, sesi_id))
        
        # Close the session
        cursor.execute("UPDATE presensi_sesi SET status = 'closed' WHERE id = %s", (sesi_id,))
        conn.commit()
        
        flash('Sesi presensi berhasil ditutup dan ketidakhadiran telah dicatat', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error: {str(e)}', 'danger')
    finally:
        cursor.close()
        conn.close()
        
    return redirect(url_for('manage_sesi'))

@app.route('/admin/sesi/<int:sesi_id>/delete', methods=['POST'])
@login_required
def delete_sesi(sesi_id):
    if current_user.role != 'admin':
        flash('Anda tidak memiliki akses', 'danger')
        return redirect(url_for('home'))
    
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        # First get the session info for confirmation
        cursor.execute("SELECT judul FROM presensi_sesi WHERE id = %s", (sesi_id,))
        sesi_info = cursor.fetchone()
        
        if not sesi_info:
            flash('Sesi tidak ditemukan', 'danger')
            return redirect(url_for('manage_sesi'))
        
        # Delete all related attendance records first
        cursor.execute("DELETE FROM presensi WHERE sesi_id = %s", (sesi_id,))
        
        # Then delete the session
        cursor.execute("DELETE FROM presensi_sesi WHERE id = %s", (sesi_id,))
        
        conn.commit()
        flash(f'Sesi presensi berhasil dihapus beserta seluruh data terkait', 'success')
        
    except Exception as e:
        conn.rollback()
        flash(f'Error: {str(e)}', 'danger')
        
    finally:
        cursor.close()
        conn.close()
        
    return redirect(url_for('manage_sesi'))

# Anggota Routes
@app.route('/anggota/dashboard')
@login_required
def anggota_dashboard():
    if current_user.role != 'anggota':
        return redirect(url_for('admin_dashboard'))
    
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Get active session info for today
    cursor.execute("""
        SELECT id, judul, tanggal, created_at
        FROM presensi_sesi 
        WHERE status = 'active' AND tanggal = CURDATE()
        ORDER BY created_at DESC LIMIT 1
    """)
    active_session = cursor.fetchone()
    
    # Initialize variables
    sudah_masuk = False
    active_session_kas_status = None
    
    # If there's an active session, check if user already attended
    if active_session:
        # Check attendance status
        cursor.execute("""
            SELECT COUNT(*) as total FROM presensi 
            WHERE user_id = %s 
            AND sesi_id = %s 
            AND status = 'masuk'
        """, (current_user.id, active_session['id']))
        sudah_masuk = cursor.fetchone()['total'] > 0
        
        # Get kas status for active session
        cursor.execute("""
            SELECT kas_paid FROM presensi 
            WHERE user_id = %s AND sesi_id = %s
            LIMIT 1
        """, (current_user.id, active_session['id']))
        kas_result = cursor.fetchone()
        if kas_result:
            active_session_kas_status = kas_result
    
    # Get attendance history with session titles and kas status
    cursor.execute("""
        SELECT p.id, p.waktu_presensi, p.status, p.kas_paid, 
               s.judul, s.tanggal
        FROM presensi p
        LEFT JOIN presensi_sesi s ON p.sesi_id = s.id
        WHERE p.user_id = %s 
        ORDER BY p.waktu_presensi DESC 
        LIMIT 10
    """, (current_user.id,))
    riwayat_presensi = cursor.fetchall()
    
    # Get total kas paid - from both "masuk" and "tidak hadir" presensi
    cursor.execute("""
        SELECT COUNT(*) as total FROM presensi
        WHERE user_id = %s AND kas_paid = TRUE AND (status = 'masuk' OR status = 'tidak hadir')
    """, (current_user.id,))
    total_kas_paid = cursor.fetchone()['total']

    # Get total kas unpaid - from both "masuk" and "tidak hadir" presensi
    cursor.execute("""
        SELECT COUNT(*) as total FROM presensi
        WHERE user_id = %s AND kas_paid = FALSE AND (status = 'masuk' OR status = 'tidak hadir')
    """, (current_user.id,))
    total_kas_unpaid = cursor.fetchone()['total']

    # Get sessions with unpaid kas - include status to distinguish absences
    cursor.execute("""
        SELECT s.id, s.judul, s.tanggal, p.status
        FROM presensi p
        JOIN presensi_sesi s ON p.sesi_id = s.id
        WHERE p.user_id = %s AND p.kas_paid = FALSE AND (p.status = 'masuk' OR p.status = 'tidak hadir')
        GROUP BY s.id, p.status
        ORDER BY s.tanggal DESC
    """, (current_user.id,))
    kas_unpaid_sessions = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('anggota/dashboard.html', 
                         active_session=active_session,
                         sudah_masuk=sudah_masuk,
                         active_session_kas_status=active_session_kas_status,
                         riwayat_presensi=riwayat_presensi,
                         total_kas_paid=total_kas_paid,
                         total_kas_unpaid=total_kas_unpaid,
                         kas_unpaid_sessions=kas_unpaid_sessions)

# API Routes
@app.route('/api/presensi', methods=['POST'])
@login_required
def create_presensi():
    if current_user.role != 'anggota':
        return jsonify({"message": "Unauthorized"}), 403
    
    data = request.get_json()
    status = data.get('status')
    
    if status not in ['masuk', 'pulang']:
        return jsonify({"message": "Status tidak valid"}), 400
    
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        # Cek apakah sudah melakukan presensi dengan status yang sama hari ini
        cursor.execute("""
            SELECT COUNT(*) FROM presensi 
            WHERE user_id = %s 
            AND DATE(waktu_presensi) = CURDATE() 
            AND status = %s
        """, (current_user.id, status))
        
        if cursor.fetchone()[0] > 0:
            return jsonify({"message": f"Anda sudah presensi {status} hari ini"}), 400
        
        # Tambahkan presensi baru
        cursor.execute("""
            INSERT INTO presensi (user_id, status)
            VALUES (%s, %s)
        """, (current_user.id, status))
        conn.commit()
        
        return jsonify({"message": f"Presensi {status} berhasil dicatat"}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"message": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/presensi', methods=['GET'])
@login_required
def get_presensi():
    if current_user.role == 'admin':
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT p.id, u.nama_lengkap, p.waktu_presensi, p.status 
            FROM presensi p
            JOIN users u ON p.user_id = u.id
            ORDER BY p.waktu_presensi DESC
        """)
        presensi = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(presensi)
    else:
        return jsonify({"message": "Unauthorized"}), 403

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        nama_lengkap = request.form.get('nama_lengkap')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validasi form
        if not all([nama_lengkap, username, password, confirm_password]):
            flash('Semua field harus diisi', 'danger')
            return redirect(url_for('register'))
            
        if password != confirm_password:
            flash('Password tidak cocok', 'danger')
            return redirect(url_for('register'))
        
        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)
            
            # Cek apakah username sudah digunakan
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                flash('Username sudah digunakan', 'danger')
                return redirect(url_for('register'))
            
            # Store password directly without hashing
            cursor.execute("""
                INSERT INTO users (nama_lengkap, username, password, role)
                VALUES (%s, %s, %s, 'anggota')
            """, (nama_lengkap, username, password))
            conn.commit()
            
            flash('Registrasi berhasil! Silakan login', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            print(f"Error during registration: {str(e)}")
            flash('Terjadi kesalahan sistem', 'danger')
            
        finally:
            if 'cursor' in locals(): cursor.close()
            if 'conn' in locals(): conn.close()
    
    return render_template('register.html')

@app.route('/presensi', methods=['POST'])
@login_required
def presensi():
    if current_user.role != 'anggota':
        flash('Unauthorized', 'danger')
        return redirect(url_for('home'))
    
    status = request.form.get('status')
    
    if status != 'masuk':
        flash('Status tidak valid', 'danger')
        return redirect(url_for('anggota_dashboard'))
    
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Check for active session
        cursor.execute("""
            SELECT id FROM presensi_sesi 
            WHERE status = 'active' AND tanggal = CURDATE()
            ORDER BY created_at DESC LIMIT 1
        """)
        active_session = cursor.fetchone()
        
        if not active_session:
            flash('Tidak ada sesi presensi aktif untuk hari ini', 'warning')
            return redirect(url_for('anggota_dashboard'))
            
        sesi_id = active_session['id']
        
        # Hapus validasi waktu presensi (jam_mulai dan jam_selesai)
        
        # Check if already done presensi for this session
        cursor.execute("""
            SELECT COUNT(*) as total FROM presensi 
            WHERE user_id = %s AND sesi_id = %s
        """, (current_user.id, sesi_id))
        
        if cursor.fetchone()['total'] > 0:
            flash('Anda sudah presensi untuk sesi ini', 'warning')
            return redirect(url_for('anggota_dashboard'))
        
        # Add new presensi with session ID
        cursor.execute("""
            INSERT INTO presensi (user_id, status, sesi_id)
            VALUES (%s, %s, %s)
        """, (current_user.id, status, sesi_id))
        conn.commit()
        
        flash('Presensi berhasil dicatat', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error: {str(e)}', 'danger')
    finally:
        cursor.close()
        conn.close()
        
    return redirect(url_for('anggota_dashboard'))

@app.route('/api/kas/update', methods=['POST'])
@login_required
def update_kas():
    if current_user.role != 'admin':
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    
    data = request.get_json()
    presensi_id = data.get('presensi_id')
    kas_paid = data.get('kas_paid', False)
    
    if not presensi_id:
        return jsonify({"status": "error", "message": "presensi_id is required"}), 400
    
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            UPDATE presensi 
            SET kas_paid = %s
            WHERE id = %s
        """, (kas_paid, presensi_id))
        conn.commit()
        
        return jsonify({"status": "success", "message": "Kas status updated successfully"})
    except Exception as e:
        conn.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/presensi/update-status', methods=['POST'])
@login_required
def update_presensi_status():
    if current_user.role != 'admin':
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    
    data = request.get_json()
    presensi_id = data.get('presensi_id')
    new_status = data.get('new_status')
    
    if not presensi_id:
        return jsonify({"status": "error", "message": "presensi_id is required"}), 400
        
    if new_status not in ['masuk', 'tidak hadir']:
        return jsonify({"status": "error", "message": "Status tidak valid"}), 400
    
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        # Update presensi status
        cursor.execute("""
            UPDATE presensi 
            SET status = %s
            WHERE id = %s
        """, (new_status, presensi_id))
        
        conn.commit()
        
        return jsonify({
            "status": "success", 
            "message": "Status presensi berhasil diubah"
        })
    except Exception as e:
        conn.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/kas-report')
@login_required
def kas_report():
    if current_user.role != 'admin':
        flash('Anda tidak memiliki akses', 'danger')
        return redirect(url_for('home'))
    
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Get total kas collected - only from "masuk" and "tidak hadir" presensi
    cursor.execute("""
        SELECT COUNT(*) as total 
        FROM presensi 
        WHERE kas_paid = TRUE AND (status = 'masuk' OR status = 'tidak hadir')
    """)
    total_kas_collected = cursor.fetchone()['total'] * 5000 + 2434500 # Rp 5000 per entry
    
    # Get kas by month - only from "masuk" and "tidak hadir" presensi
    cursor.execute("""
        SELECT 
            DATE_FORMAT(waktu_presensi, '%Y-%m') as month,
            COUNT(*) as count
        FROM presensi
        WHERE kas_paid = TRUE AND (status = 'masuk' OR status = 'tidak hadir')
        GROUP BY DATE_FORMAT(waktu_presensi, '%Y-%m')
        ORDER BY month DESC
    """)
    monthly_kas = cursor.fetchall()
    
    # Get users with most unpaid kas - from "masuk" and "tidak hadir" presensi
    cursor.execute("""
        SELECT 
            u.nama_lengkap,
            COUNT(*) as unpaid_count
        FROM presensi p
        JOIN users u ON p.user_id = u.id
        WHERE p.kas_paid = FALSE AND (p.status = 'masuk' OR p.status = 'tidak hadir')
        GROUP BY p.user_id
        ORDER BY unpaid_count DESC
        LIMIT 5
    """)
    top_unpaid_users = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('admin/kas_report.html', 
                         total_kas_collected=total_kas_collected,
                         monthly_kas=monthly_kas,
                         top_unpaid_users=top_unpaid_users)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)