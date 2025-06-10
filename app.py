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

# Anggota Routes
@app.route('/anggota/dashboard')
@login_required
def anggota_dashboard():
    if current_user.role != 'anggota':
        return redirect(url_for('admin_dashboard'))
    
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("""
        SELECT COUNT(*) as total FROM presensi 
        WHERE user_id = %s 
        AND DATE(waktu_presensi) = CURDATE() 
        AND status = 'masuk'
    """, (current_user.id,))
    sudah_masuk = cursor.fetchone()['total'] > 0
    
    cursor.execute("""
        SELECT COUNT(*) as total FROM presensi 
        WHERE user_id = %s 
        AND DATE(waktu_presensi) = CURDATE() 
        AND status = 'pulang'
    """, (current_user.id,))
    sudah_pulang = cursor.fetchone()['total'] > 0
    
    cursor.execute("""
        SELECT waktu_presensi, status 
        FROM presensi 
        WHERE user_id = %s 
        ORDER BY waktu_presensi DESC 
        LIMIT 5
    """, (current_user.id,))
    riwayat_presensi = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('anggota/dashboard.html', 
                         sudah_masuk=sudah_masuk,
                         sudah_pulang=sudah_pulang,
                         riwayat_presensi=riwayat_presensi)

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
    
    if status not in ['masuk', 'pulang']:
        flash('Status tidak valid', 'danger')
        return redirect(url_for('anggota_dashboard'))
    
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        # Check if already done presensi with same status today
        cursor.execute("""
            SELECT COUNT(*) FROM presensi 
            WHERE user_id = %s 
            AND DATE(waktu_presensi) = CURDATE() 
            AND status = %s
        """, (current_user.id, status))
        
        if cursor.fetchone()[0] > 0:
            flash(f'Anda sudah presensi {status} hari ini', 'warning')
            return redirect(url_for('anggota_dashboard'))
        
        # Add new presensi
        cursor.execute("""
            INSERT INTO presensi (user_id, status)
            VALUES (%s, %s)
        """, (current_user.id, status))
        conn.commit()
        
        flash(f'Presensi {status} berhasil dicatat', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error: {str(e)}', 'danger')
    finally:
        cursor.close()
        conn.close()
        
    return redirect(url_for('anggota_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)