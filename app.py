import os
import io
import base64
import pyotp
import qrcode
from flask import Flask, render_template, redirect, url_for, request, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash

from flask_talisman import Talisman
import re

# Initialize Flask app
app = Flask(__name__)

# Content Security Policy
csp = {
    'default-src': '\'self\'',
    'style-src': [
        '\'self\'',
        'https://cdn.jsdelivr.net'
    ],
    'script-src': [
        '\'self\'',
        'https://cdn.jsdelivr.net'
    ]
}

Talisman(app, content_security_policy=csp)

# Configuration
# Security: Secret key should be a strong random value. In production, use os.environ.get('SECRET_KEY')
app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Session Security
app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent JavaScript access to session cookie (XSS protection)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Prevent CSRF in cross-site contexts

# Initialize Extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    mfa_secret = db.Column(db.String(32), nullable=False) # Store MFA secret for TOTP

    def set_password(self, password):
        # Security: Use scrypt or pbkdf2 via werkzeug for password hashing to prevent rainbow table attacks.
        # Werkzeug automatically handles salt generation and storage within the hash string.
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Forms (Flask-WTF for CSRF protection)
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long.")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match.')
    ])
    submit = SubmitField('Register')

    def validate_username(self, username):
        # Security: Check if username exists using ORM to prevent SQL Injection
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already taken.')

    def validate_email(self, email):
        # Security: Check if email exists using ORM
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered.')

    def validate_password(self, password):
        # Security: Enforce password complexity (min 8 chars, 1 special char)
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password.data):
            raise ValidationError("Password must contain at least one special character.")

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class MFAForm(FlaskForm):
    otp = StringField('Enter 6-digit Code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long.")
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(),
        EqualTo('new_password', message='Passwords must match.')
    ])
    submit = SubmitField('Change Password')

# Routes
@app.route('/')
@login_required
def index():
    return render_template('base.html', content=f"<h1>Welcome, {current_user.username}!</h1><p>You have securely logged in.</p>")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        # Generate MFA Secret
        mfa_secret = pyotp.random_base32()
        
        # Store registration data in session temporarily
        session['register_username'] = form.username.data
        session['register_email'] = form.email.data
        # Hash password before storing in session for security
        # Security: Use scrypt or pbkdf2 via werkzeug for password hashing to prevent rainbow table attacks.
        # Werkzeug automatically handles salt generation and storage within the hash string.
        session['register_password_hash'] = generate_password_hash(form.password.data)
        session['register_mfa_secret'] = mfa_secret
        
        return redirect(url_for('register_verify'))
        
    return render_template('register.html', form=form)

@app.route('/register/verify', methods=['GET', 'POST'])
def register_verify():
    if 'register_mfa_secret' not in session:
        return redirect(url_for('register'))
    
    form = MFAForm()
    mfa_secret = session['register_mfa_secret']
    
    if form.validate_on_submit():
        totp = pyotp.TOTP(mfa_secret)
        if totp.verify(form.otp.data, valid_window=1):
            # Create User
            user = User(
                username=session['register_username'], 
                email=session['register_email'], 
                mfa_secret=mfa_secret,
                password_hash=session['register_password_hash']
            )
            db.session.add(user)
            db.session.commit()
            
            # Clear session and login
            session.pop('register_username', None)
            session.pop('register_email', None)
            session.pop('register_password_hash', None)
            session.pop('register_mfa_secret', None)
            
            login_user(user)
            flash('Registration successful! You are now logged in.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid MFA code. Please try again.', 'danger')

    # Generate QR Code for display
    totp_uri = pyotp.totp.TOTP(mfa_secret).provisioning_uri(name=session['register_email'], issuer_name="SecureApp")
    qr = qrcode.make(totp_uri)
    buffered = io.BytesIO()
    qr.save(buffered, format="PNG")
    qr_b64 = base64.b64encode(buffered.getvalue()).decode("utf-8")
    
    return render_template('register_verify.html', form=form, qr_code=qr_b64)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            # Password correct, now do MFA
            # Store user_id in session temporarily to verify MFA
            session['pre_2fa_user_id'] = user.id
            return redirect(url_for('mfa_verify'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/mfa', methods=['GET', 'POST'])
def mfa_verify():
    if 'pre_2fa_user_id' not in session:
        return redirect(url_for('login'))
    
    form = MFAForm()
    if form.validate_on_submit():
        user_id = session.get('pre_2fa_user_id')
        user = User.query.get(user_id)
        
        totp = pyotp.TOTP(user.mfa_secret)
        # Security: valid_window=1 allows for a 30-second clock skew (prev/next code) to prevent timeouts
        if totp.verify(form.otp.data, valid_window=1):
            # MFA correct, log user in
            login_user(user)
            session.pop('pre_2fa_user_id', None)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid MFA code.', 'danger')
            
    return render_template('mfa.html', form=form)

@app.route('/verify')
def verify():
    return redirect(url_for('mfa_verify'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash('Incorrect current password.', 'danger')
        else:
            # Security: Validate new password complexity
            if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", form.new_password.data):
                flash("Password must contain at least one special character.", 'danger')
            else:
                current_user.set_password(form.new_password.data)
                db.session.commit()
                flash('Your password has been updated!', 'success')
                return redirect(url_for('index'))
    return render_template('change_password.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        if not os.path.exists('users.db'):
            db.create_all()
            print("Database initialized successfully.")
    app.run(debug=True)
