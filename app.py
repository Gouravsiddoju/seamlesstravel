
import os
import io
import base64
import secrets
from datetime import date, datetime
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode
from PIL import Image
import requests
try:
    import pytesseract
except ImportError:
    pytesseract = None


# --- App Configuration ---
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = 'Techoptima'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'travel.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'uploads') # Folder to store temporary uploads

# This is the secret key that authorized scanners (e.g., airport gates) must provide.
VALIDATOR_API_KEY = "Techoptima"

# Ensure the instance and upload folders exist
for folder in [os.path.join(basedir, 'instance'), app.config['UPLOAD_FOLDER']]:
    if not os.path.exists(folder):
        os.makedirs(folder)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    unique_token = db.Column(db.String(100), unique=True, nullable=False)
    is_identity_verified = db.Column(db.Boolean, default=False)
    passport = db.relationship('Passport', backref='user', uselist=False, cascade="all, delete-orphan")
    aadhaar = db.relationship('AadhaarCard', backref='user', uselist=False, cascade="all, delete-orphan")
    driving_license = db.relationship('DrivingLicense', backref='user', uselist=False, cascade="all, delete-orphan")
    boarding_passes = db.relationship('BoardingPass', backref='user', lazy=True, cascade="all, delete-orphan")

class Passport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    passport_number = db.Column(db.String(50), unique=True, nullable=False)
    full_name = db.Column(db.String(150), nullable=False)
    nationality = db.Column(db.String(50), nullable=False)
    expiry_date = db.Column(db.Date, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)

class AadhaarCard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    aadhaar_number = db.Column(db.String(14), unique=True, nullable=False)
    full_name = db.Column(db.String(150), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)

class DrivingLicense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    license_number = db.Column(db.String(50), unique=True, nullable=False)
    full_name = db.Column(db.String(150), nullable=False)
    expiry_date = db.Column(db.Date, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)

class BoardingPass(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    flight_number = db.Column(db.String(20), nullable=False)
    seat = db.Column(db.String(10), nullable=False)
    gate = db.Column(db.String(10), nullable=False)
    boarding_time = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials. Please try again.')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        if User.query.filter_by(email=email).first():
            flash('Email address already registered.')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(
            username=username,
            email=email,
            password_hash=hashed_password,
            unique_token=secrets.token_hex(16)
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    validation_url = url_for('validate_user', token=current_user.unique_token, _external=True)
    logo_url = 'https://thfvnext.bing.com/th/id/OIP.o6w5rOxIrkHh7mkgjUQEmAHaGz?w=212&h=180&c=7&r=0&o=5&cb=thfvnext&dpr=1.2&pid=1.7'
    qr_img_data = generate_qr_with_logo(validation_url, logo_url)
    return render_template('dashboard.html', user=current_user, qr_code=qr_img_data)

@app.route('/add_passport', methods=['GET', 'POST'])
@login_required
def add_passport():
    # ADDED THIS CHECK TO PREVENT DUPLICATES
    if current_user.passport:
        flash('You have already added a passport. Only one is allowed per user.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        new_passport = Passport(
            passport_number=request.form.get('passport_number'),
            full_name=request.form.get('full_name'),
            nationality=request.form.get('nationality'),
            expiry_date=datetime.strptime(request.form.get('expiry_date'), '%Y-%m-%d').date(),
            user_id=current_user.id
        )
        db.session.add(new_passport)
        db.session.commit()
        flash('Passport details saved!')
        return redirect(url_for('dashboard'))
    return render_template('add_passport.html')

@app.route('/add_aadhaar', methods=['GET', 'POST'])
@login_required
def add_aadhaar():
    # ADDED THIS CHECK TO PREVENT DUPLICATES
    if current_user.aadhaar:
        flash('You have already added an Aadhaar card.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        new_aadhaar = AadhaarCard(
            aadhaar_number=request.form.get('aadhaar_number'),
            full_name=request.form.get('full_name'),
            date_of_birth=datetime.strptime(request.form.get('date_of_birth'), '%Y-%m-%d').date(),
            user_id=current_user.id
        )
        db.session.add(new_aadhaar)
        db.session.commit()
        flash('Aadhaar details saved!')
        return redirect(url_for('dashboard'))
    return render_template('add_aadhaar.html')

@app.route('/add_driving_license', methods=['GET', 'POST'])
@login_required
def add_driving_license():
    if request.method == 'POST':
        new_license = DrivingLicense(
            license_number=request.form.get('license_number'),
            full_name=request.form.get('full_name'),
            expiry_date=datetime.strptime(request.form.get('expiry_date'), '%Y-%m-%d').date(),
            user_id=current_user.id
        )
        db.session.add(new_license)
        db.session.commit()
        flash('Driving License details saved!')
        return redirect(url_for('dashboard'))
    return render_template('add_driving_license.html')

@app.route('/add_boarding_pass', methods=['GET', 'POST'])
@login_required
def add_boarding_pass():
    if request.method == 'POST':
        new_bp = BoardingPass(
            flight_number=request.form.get('flight_number'),
            seat=request.form.get('seat'),
            gate=request.form.get('gate'),
            boarding_time=datetime.strptime(request.form.get('boarding_time'), '%Y-%m-%dT%H:%M'),
            user_id=current_user.id
        )
        db.session.add(new_bp)
        db.session.commit()
        flash('Boarding pass details saved!')
        return redirect(url_for('dashboard'))
    return render_template('add_boarding_pass.html')

@app.route('/verify_identity', methods=['GET', 'POST'])
@login_required
def verify_identity():
    if not current_user.passport or (not current_user.aadhaar and not current_user.driving_license):
        flash('Please upload your Passport and a second ID (Aadhaar or License) before starting verification.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        id_doc = request.files.get('id_document')
        selfie = request.files.get('selfie')

        if not id_doc or not selfie:
            flash('Both a photo of your passport and a selfie are required.')
            return redirect(url_for('verify_identity'))

        # --- SIMULATION ---
        # The real validation logic has been removed as requested.
        # This now simulates a successful verification.
        current_user.is_identity_verified = True
        db.session.commit()
        flash('Identity verification submitted and approved (simulation)!')

        return redirect(url_for('dashboard'))

    return render_template('verify_identity.html')


@app.route('/validate/<token>')
def validate_user(token):
    api_key = request.args.get('api_key')
    if api_key != VALIDATOR_API_KEY:
        return "<h1>Access Denied: Invalid API Key</h1>", 403

    user = User.query.filter_by(unique_token=token).first()
    if user:
        return render_template('validate.html', user=user)
    else:
        return "<h1>Access Denied: Invalid Token</h1>", 401

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

def generate_qr_with_logo(data_string, logo_url):
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H)
    qr.add_data(data_string)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white").convert('RGBA')
    try:
        logo_response = requests.get(logo_url, stream=True)
        logo_response.raise_for_status()
        logo_img_raw = Image.open(logo_response.raw).convert('RGBA')
        logo_size = 64
        logo_img = logo_img_raw.resize((logo_size, logo_size))
        pos = ((qr_img.size[0] - logo_size) // 2, (qr_img.size[1] - logo_size) // 2)
        background = Image.new('RGBA', (logo_size + 8, logo_size + 8), (255, 255, 255, 255))
        qr_img.paste(background, (pos[0]-4, pos[1]-4))
        qr_img.paste(logo_img, pos, logo_img)
    except requests.exceptions.RequestException as e:
        print(f"Warning: Could not fetch logo. Error: {e}")
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode('utf-8')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', debug=True)
