import os
import re
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'trustvault-secret-key-2026')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

ALLOWED_EXTENSIONS = {'pdf', 'docx', 'doc', 'png', 'jpg', 'jpeg', 'txt', 'csv', 'xlsx'}
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

if os.environ.get('RENDER'):
    db_path = '/tmp/trustvault.db'
    upload_path = '/tmp/uploads'
else:
    db_path = os.path.join(BASE_DIR, 'trustvault.db')
    upload_path = os.path.join(BASE_DIR, 'uploads')

app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = upload_path

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_password_strength(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character."
    return True, "Password is strong."

def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr or '127.0.0.1'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'admin', 'user', 'viewer'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(50), nullable=False, default='General')
    file_size = db.Column(db.Integer, default=0) # stored in bytes
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    owner = db.relationship('User', backref=db.backref('documents', lazy=True))

class DocumentAccess(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    can_read = db.Column(db.Boolean, default=True)
    can_write = db.Column(db.Boolean, default=False)
    can_delete = db.Column(db.Boolean, default=False)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def log_action(username, action, user_id=None):
    ip = get_client_ip()
    log = AuditLog(username=username, action=action, ip_address=ip, user_id=user_id)
    db.session.add(log)
    db.session.commit()

@app.before_request
def initialize_database():
    if not getattr(app, '_db_initialized', False):
        db.create_all()
        app._db_initialized = True

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        terms_accepted = request.form.get('terms')

        if not terms_accepted:
            flash('You must agree to the Terms & Conditions to register.', 'error')
            return redirect(url_for('register'))

        is_strong, msg = validate_password_strength(password)
        if not is_strong:
            flash(msg, 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username is already taken. Please choose another.', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email address is already registered.', 'error')
            return redirect(url_for('register'))

        user_count = User.query.count()
        role = 'admin' if user_count == 0 else 'user'

        new_user = User(username=username, email=email, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        log_action(username=new_user.username, action=f"Account created with role '{role}'", user_id=new_user.id)
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            log_action(username=user.username, action="Successful login authentication", user_id=user.id)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))

        log_action(username=username or "Anonymous", action="Failed login authentication attempt")
        flash('Invalid username or password credentials.', 'error')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_action(username=current_user.username, action="User session logged out", user_id=current_user.id)
    logout_user()
    flash('Logged successfully out.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    total_docs = Document.query.count()
    total_users = User.query.count()
    
    # Calculate storage consumption against a 100MB limit (104857600 bytes)
    total_bytes = db.session.query(db.func.sum(Document.file_size)).scalar() or 0
    max_storage_bytes = 100 * 1024 * 1024 
    storage_percentage = min(round((total_bytes / max_storage_bytes) * 100, 1), 100.0)
    storage_used_mb = round(total_bytes / (1024 * 1024), 2)

    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(5).all()
    return render_template('dashboard.html', total_docs=total_docs, total_users=total_users, 
                           storage_percentage=storage_percentage, storage_used_mb=storage_used_mb, logs=logs)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if current_user.role == 'viewer':
        flash('Viewer role is read-only. File uploads are disabled.', 'error')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file payload selected.', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        title = request.form.get('title', '').strip()
        category = request.form.get('category', 'General').strip()

        if file.filename == '':
            flash('No file selected.', 'error')
            return redirect(request.url)

        if not allowed_file(file.filename):
            flash(f"Invalid file type. Allowed: {', '.join(ALLOWED_EXTENSIONS)}", 'error')
            return redirect(request.url)

        filename = secure_filename(file.filename)
        saved_filename = datetime.now().strftime("%Y%m%d%H%M%S_") + filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], saved_filename)
        file.save(file_path)
        file_size = os.path.getsize(file_path)

        new_doc = Document(title=title if title else filename, filename=saved_filename, category=category, file_size=file_size, owner_id=current_user.id)
        db.session.add(new_doc)
        db.session.commit()

        log_action(username=current_user.username, action=f"Uploaded encrypted vault asset '{new_doc.title}'", user_id=current_user.id)
        flash('Document uploaded successfully!', 'success')
        return redirect(url_for('my_documents'))

    return render_template('upload.html')

@app.route('/my-documents')
@login_required
def my_documents():
    my_docs = Document.query.filter_by(owner_id=current_user.id).all()
    shared_accesses = DocumentAccess.query.filter_by(user_id=current_user.id, can_read=True).all()
    shared_doc_ids = [sa.document_id for sa in shared_accesses]
    shared_docs = Document.query.filter(Document.id.in_(shared_doc_ids)).all() if shared_doc_ids else []
    all_users = User.query.filter(User.id != current_user.id).all()
    
    # Fetch existing permissions for document matrix configuration
    doc_permissions = {}
    for doc in my_docs:
        doc_permissions[doc.id] = {sa.user_id: sa for sa in DocumentAccess.query.filter_by(document_id=doc.id).all()}

    return render_template('my_documents.html', my_docs=my_docs, shared_docs=shared_docs, all_users=all_users, doc_permissions=doc_permissions)

@app.route('/share/<int:doc_id>', methods=['POST'])
@login_required
def share_document(doc_id):
    if current_user.role == 'viewer':
        flash('Viewers cannot configure access permissions.', 'error')
        return redirect(url_for('my_documents'))

    doc = Document.query.get_or_404(doc_id)
    if doc.owner_id != current_user.id and current_user.role != 'admin':
        flash('Access denied. Only document owners or admins can manage permissions.', 'error')
        return redirect(url_for('my_documents'))

    target_user_id = request.form.get('user_id')
    can_read = 'can_read' in request.form
    can_write = 'can_write' in request.form
    can_delete = 'can_delete' in request.form

    access = DocumentAccess.query.filter_by(document_id=doc_id, user_id=target_user_id).first()
    if not access:
        access = DocumentAccess(document_id=doc_id, user_id=target_user_id, can_read=can_read, can_write=can_write, can_delete=can_delete)
        db.session.add(access)
    else:
        access.can_read = can_read
        access.can_write = can_write
        access.can_delete = can_delete
    
    db.session.commit()
    log_action(username=current_user.username, action=f"Updated granular file-level matrix permissions for document ID {doc_id}", user_id=current_user.id)
    flash('File access control matrix updated successfully.', 'success')
    return redirect(url_for('my_documents'))

@app.route('/download/<int:doc_id>')
@login_required
def download_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    access = DocumentAccess.query.filter_by(document_id=doc_id, user_id=current_user.id, can_read=True).first()
    
    if doc.owner_id != current_user.id and current_user.role != 'admin' and not access:
        flash('Access denied. Missing read permission.', 'error')
        return redirect(url_for('my_documents'))

    log_action(username=current_user.username, action=f"Downloaded secure vault asset '{doc.title}'", user_id=current_user.id)
    return send_from_directory(app.config['UPLOAD_FOLDER'], doc.filename, as_attachment=True)

@app.route('/delete/<int:doc_id>', methods=['POST'])
@login_required
def delete_document(doc_id):
    if current_user.role == 'viewer':
        flash('Viewer role is read-only. File deletion blocked.', 'error')
        return redirect(url_for('my_documents'))

    doc = Document.query.get_or_404(doc_id)
    access = DocumentAccess.query.filter_by(document_id=doc_id, user_id=current_user.id, can_delete=True).first()

    if doc.owner_id != current_user.id and current_user.role != 'admin' and not access:
        flash('Access denied. You do not hold delete privileges for this asset.', 'error')
        return redirect(url_for('my_documents'))

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], doc.filename)
    if os.path.exists(file_path):
        os.remove(file_path)

    DocumentAccess.query.filter_by(document_id=doc_id).delete()
    db.session.delete(doc)
    db.session.commit()

    log_action(username=current_user.username, action=f"Permanently purged vault asset '{doc.title}'", user_id=current_user.id)
    flash('Document deleted successfully.', 'success')
    return redirect(url_for('my_documents'))

@app.route('/search')
@login_required
def search_documents():
    query = request.args.get('q', '').strip()
    category = request.args.get('category', '').strip()

    docs = Document.query
    if query:
        docs = docs.filter(Document.title.ilike(f'%{query}%'))
    if category:
        docs = docs.filter(Document.category.ilike(f'%{category}%'))

    results = docs.all()
    visible_results = []
    for doc in results:
        access = DocumentAccess.query.filter_by(document_id=doc.id, user_id=current_user.id, can_read=True).first()
        if doc.owner_id == current_user.id or current_user.role == 'admin' or access:
            visible_results.append(doc)

    return render_template('search.html', documents=visible_results, query=query, category=category)

@app.route('/audit-logs')
@login_required
def audit_logs():
    if current_user.role != 'admin':
        flash('Access denied. Audit logs are restricted to Admin role users.', 'error')
        return redirect(url_for('dashboard'))

    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('logs.html', logs=logs)

if __name__ == '__main__':
    app.run(debug=True)