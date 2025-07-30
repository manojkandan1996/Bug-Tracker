from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config.update(
    SECRET_KEY='devkey',
    SQLALCHEMY_DATABASE_URI='sqlite:///bugtracker.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    # Email config (use your SMTP details)
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv('EMAIL_USER'),
    MAIL_PASSWORD=os.getenv('EMAIL_PASS'),
)

db = SQLAlchemy(app)
mail = Mail(app)
login = LoginManager(app)
login.login_view = 'login'

# --- Models ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    bugs_assigned = db.relationship('Bug', backref='assignee', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Bug(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='Open')
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

# --- User loader ---

@login.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Helper: send emails ---

def send_email(subject, recipients, body):
    msg = Message(subject, recipients=recipients)
    msg.body = body
    mail.send(msg)

# --- Routes ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if User.query.filter((User.username==username) | (User.email==email)).first():
            flash('User already exists', 'danger')
            return redirect(url_for('register'))
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    if current_user.is_admin:
        bugs = Bug.query.all()
    else:
        bugs = Bug.query.filter(
            (Bug.assignee_id == current_user.id) | (Bug.assignee_id == None)
        ).all()
    users = User.query.all()
    return render_template('dashboard.html', bugs=bugs, users=users)

@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        priority = request.form['priority']
        bug = Bug(title=title, description=description, priority=priority)
        db.session.add(bug)
        db.session.commit()
        flash('Bug reported!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('report.html')

@app.route('/assign/<int:bug_id>', methods=['POST'])
@login_required
def assign(bug_id):
    if not current_user.is_admin:
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))
    bug = Bug.query.get_or_404(bug_id)
    user_id = request.form.get('assignee_id')
    user = User.query.get(user_id) if user_id else None
    bug.assignee_id = user.id if user else None
    db.session.commit()
    if user:
        send_email(
            "Bug Assigned to You",
            [user.email],
            f"You have been assigned bug #{bug.id}: {bug.title}"
        )
    flash('Bug assignment updated.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/status/<int:bug_id>', methods=['POST'])
@login_required
def update_status(bug_id):
    bug = Bug.query.get_or_404(bug_id)
    status = request.form.get('status')
    if status not in ['Open', 'Fixed']:
        flash('Invalid status', 'danger')
        return redirect(url_for('dashboard'))
    bug.status = status
    db.session.commit()
    # Notify assignee on status update
    if bug.assignee and bug.assignee.email:
        send_email(
            "Bug Status Updated",
            [bug.assignee.email],
            f"Status for bug #{bug.id} '{bug.title}' changed to {status}."
        )
    flash('Status updated.', 'success')
    return redirect(url_for('dashboard'))

# --- Run ---

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
