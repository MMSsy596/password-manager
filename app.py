from flask import Flask, render_template, request, redirect, url_for, flash, session
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

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
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
        
        user = User(username=username, password_hash=generate_password_hash(password))
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

if __name__ == '__main__':
    with app.app_context():
        # db.create_all() # Di chuyển dòng này ra ngoài
        pass # Giữ lại khối này nếu cần các lệnh khác chỉ chạy khi script được gọi trực tiếp
    app.run(debug=True)

with app.app_context():
    db.create_all() 