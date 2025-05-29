from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import os
from datetime import datetime
from translations.vi import translations as vi_translations
from translations.en import translations as en_translations
from translations.zh import translations as zh_translations
import csv
from io import StringIO
import json
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///passwords.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Tạo hoặc đọc key mã hóa
KEY_FILE = 'encryption.key'
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, 'rb') as f:
        key = f.read()
else:
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(key)

cipher_suite = Fernet(key)

# Cấu hình ngôn ngữ
LANGUAGES = {
    'vi': vi_translations,
    'en': en_translations,
    'zh': zh_translations
}

def get_translation(key):
    lang = session.get('language', 'vi')
    return LANGUAGES[lang].get(key, key)

@app.context_processor
def utility_processor():
    return dict(_=get_translation)

# Decorator cho admin
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash(get_translation('admin_required'))
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    passwords = db.relationship('Password', backref='user', lazy=True)

class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    encrypted_password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash(get_translation('username_exists'))
            return redirect(url_for('register'))
        
        # Người dùng đầu tiên đăng ký sẽ là admin
        is_admin = not User.query.first() 
        user = User(username=username, password_hash=generate_password_hash(password), is_admin=is_admin)
        db.session.add(user)
        db.session.commit()
        
        flash(get_translation('registration_success'))
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        
        flash(get_translation('login_error'))
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    search_query = request.args.get('search', '').strip()
    passwords = Password.query.filter_by(user_id=current_user.id)
    
    if search_query:
        passwords = passwords.filter(
            (Password.title.ilike(f'%{search_query}%')) |
            (Password.username.ilike(f'%{search_query}%'))
        )
    
    # Nhóm mật khẩu theo tiêu đề
    grouped_passwords = {}
    for password in passwords.all():
        if password.title not in grouped_passwords:
            grouped_passwords[password.title] = []
        grouped_passwords[password.title].append(password)
    
    return render_template('dashboard.html', 
                         grouped_passwords=grouped_passwords,
                         search_query=search_query,
                         cipher_suite=cipher_suite)

@app.route('/add_password', methods=['GET', 'POST'])
@login_required
def add_password():
    if request.method == 'POST':
        title = request.form['title']
        username = request.form['username']
        password = request.form['password']
        
        encrypted_password = cipher_suite.encrypt(password.encode())
        new_password = Password(
            title=title,
            username=username,
            encrypted_password=encrypted_password,
            user_id=current_user.id
        )
        
        db.session.add(new_password)
        db.session.commit()
        flash(get_translation('password_added'))
        return redirect(url_for('dashboard'))
    
    return render_template('add_password.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/set_language/<lang>')
def set_language(lang):
    if lang in LANGUAGES:
        session['language'] = lang
    return redirect(request.referrer or url_for('index'))

@app.route('/set_theme/<theme>')
def set_theme(theme):
    if theme in ['light', 'dark', 'system']:
        session['theme'] = theme
    return redirect(request.referrer or url_for('index'))

@app.route('/edit_password/<int:password_id>', methods=['GET', 'POST'])
@login_required
def edit_password(password_id):
    password = Password.query.get_or_404(password_id)
    if password.user_id != current_user.id:
        flash(get_translation('unauthorized'))
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        password.title = request.form['title']
        password.username = request.form['username']
        new_password = request.form['password']
        if new_password:
            password.encrypted_password = cipher_suite.encrypt(new_password.encode())
        
        db.session.commit()
        flash(get_translation('password_updated'))
        return redirect(url_for('dashboard'))
    
    return render_template('edit_password.html', password=password, 
                         decrypted_password=cipher_suite.decrypt(password.encrypted_password).decode())

@app.route('/delete_password/<int:password_id>')
@login_required
def delete_password(password_id):
    password = Password.query.get_or_404(password_id)
    if password.user_id != current_user.id:
        flash(get_translation('unauthorized'))
        return redirect(url_for('dashboard'))
    
    db.session.delete(password)
    db.session.commit()
    flash(get_translation('password_deleted'))
    return redirect(url_for('dashboard'))

@app.route('/export_passwords')
@login_required
def export_passwords():
    passwords = Password.query.filter_by(user_id=current_user.id).all()
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['title', 'username', 'password'])
    for password in passwords:
        decrypted_password = cipher_suite.decrypt(password.encrypted_password).decode()
        cw.writerow([password.title, password.username, decrypted_password])

    output = si.getvalue()
    response = app.make_response(output)
    response.headers['Content-Disposition'] = 'attachment; filename=passwords.csv'
    response.headers['Content-type'] = 'text/csv'
    return response

@app.route('/import_passwords', methods=['GET', 'POST'])
@login_required
def import_passwords():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash(get_translation('no_file_part'))
            return redirect(url_for('dashboard'))
        file = request.files['file']
        if file.filename == '':
            flash(get_translation('no_selected_file'))
            return redirect(url_for('dashboard'))
        if file and file.filename.endswith('.csv'):
            stream = StringIO(file.stream.read().decode("UTF8"))
            reader = csv.reader(stream)
            next(reader) # Skip header row
            imported_count = 0
            for row in reader:
                try:
                    title, username, password_text = row
                    encrypted_password = cipher_suite.encrypt(password_text.encode())
                    new_password = Password(
                        title=title,
                        username=username,
                        encrypted_password=encrypted_password,
                        user_id=current_user.id
                    )
                    db.session.add(new_password)
                    imported_count += 1
                except Exception as e:
                    # Log error or handle specific CSV format issues
                    print(f"Error importing row: {row} - {e}")
                    flash(get_translation('import_row_error').format(row=row, error=e))

            db.session.commit()
            flash(get_translation('import_success').format(count=imported_count))
            return redirect(url_for('dashboard'))
        else:
            flash(get_translation('invalid_file_format'))
            return redirect(url_for('dashboard'))

    return render_template('import_passwords.html')

# Admin routes

@app.route('/admin/backup')
@admin_required
def admin_backup():
    all_passwords = Password.query.all()
    backup_data = []
    for password in all_passwords:
        try:
            decrypted_password = cipher_suite.decrypt(password.encrypted_password).decode()
        except Exception:
            # Handle potential decryption errors for old/corrupted data
            decrypted_password = "[DECRYPTION FAILED]"

        backup_data.append({
            'user_id': password.user_id,
            'title': password.title,
            'username': password.username,
            'password': decrypted_password,
            'created_at': password.created_at.isoformat()
        })

    response = app.make_response(json.dumps(backup_data, indent=4))
    response.headers['Content-Disposition'] = 'attachment; filename=password_backup.json'
    response.headers['Content-type'] = 'application/json'
    return response

@app.route('/admin/restore', methods=['GET', 'POST'])
@admin_required
def admin_restore():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash(get_translation('no_file_part'))
            return redirect(url_for('admin_restore'))
        file = request.files['file']
        if file.filename == '':
            flash(get_translation('no_selected_file'))
            return redirect(url_for('admin_restore'))

        if file and file.filename.endswith('.json'):
            try:
                backup_data = json.loads(file.stream.read().decode("utf-8"))
                imported_count = 0
                # Optional: Clear existing data before import if desired
                # db.session.query(Password).delete()
                # db.session.query(User).delete()
                # db.session.commit()

                # Note: This simple restore assumes user_id still exists or handles creation.
                # A more robust solution might match users by username or handle mapping.
                # For this example, we'll rely on user_id existing.

                for entry in backup_data:
                    try:
                        # Check if user_id exists before creating password
                        user_exists = User.query.get(entry['user_id'])
                        if not user_exists:
                             print(f"Warning: User with ID {entry['user_id']} not found. Skipping password for {entry['title']}.")
                             flash(get_translation('restore_user_not_found').format(user_id=entry['user_id'], title=entry['title']))
                             continue

                        encrypted_password = cipher_suite.encrypt(entry['password'].encode())
                        # Attempt to parse created_at, default to now if failed
                        created_at = datetime.fromisoformat(entry['created_at']) if 'created_at' in entry else datetime.utcnow()

                        new_password = Password(
                            user_id=entry['user_id'],
                            title=entry['title'],
                            username=entry['username'],
                            encrypted_password=encrypted_password,
                            created_at=created_at
                        )
                        db.session.add(new_password)
                        imported_count += 1
                    except Exception as e:
                        print(f"Error importing entry: {entry} - {e}")
                        flash(get_translation('restore_entry_error').format(entry=entry, error=e))
                        # Decide whether to rollback or continue on error
                        db.session.rollback() # Rollback the current transaction
                        # Or continue: pass

                db.session.commit()
                flash(get_translation('restore_success').format(count=imported_count))
                return redirect(url_for('dashboard')) # Redirect to dashboard or admin page

            except json.JSONDecodeError:
                 flash(get_translation('invalid_json_format'))
            except Exception as e:
                 flash(get_translation('restore_failed').format(error=e))
                 print(f"Restore failed: {e}")

            return redirect(url_for('admin_restore'))
        else:
            flash(get_translation('invalid_file_format'))
            return redirect(url_for('admin_restore'))

    return render_template('admin/restore.html')

if __name__ == '__main__':
    with app.app_context():
        # db.create_all() # Di chuyển dòng này ra ngoài
        pass # Giữ lại khối này nếu cần các lệnh khác chỉ chạy khi script được gọi trực tiếp
    app.run(debug=True)

with app.app_context():
    db.create_all() 