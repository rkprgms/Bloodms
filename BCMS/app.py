from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import csv
from io import StringIO
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bloodbank.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    user_type = db.Column(db.String(20), nullable=False)  # admin, donor, recipient
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Donor specific fields
    full_name = db.Column(db.String(100))
    phone = db.Column(db.String(15))
    blood_group = db.Column(db.String(5))
    age = db.Column(db.Integer)
    weight = db.Column(db.Float)
    last_donation = db.Column(db.DateTime)
    medical_history = db.Column(db.Text)
    address = db.Column(db.Text)
    
    # Recipient specific fields
    hospital_name = db.Column(db.String(100))
    patient_name = db.Column(db.String(100))
    urgency_level = db.Column(db.String(20))  # low, medium, high, emergency

class BloodStock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    blood_group = db.Column(db.String(5), nullable=False)
    units_available = db.Column(db.Integer, default=0)
    expiry_date = db.Column(db.DateTime)
    collection_date = db.Column(db.DateTime, default=datetime.utcnow)
    donor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(20), default='available')  # available, expired, used

class BloodRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    blood_group = db.Column(db.String(5), nullable=False)
    units_needed = db.Column(db.Integer, nullable=False)
    urgency_level = db.Column(db.String(20), nullable=False)
    patient_name = db.Column(db.String(100))
    hospital_name = db.Column(db.String(100))
    contact_phone = db.Column(db.String(15))
    status = db.Column(db.String(20), default='pending')  # pending, approved, denied, fulfilled
    request_date = db.Column(db.DateTime, default=datetime.utcnow)
    admin_notes = db.Column(db.Text)

class DonationAppointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    appointment_date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='scheduled')  # scheduled, completed, cancelled
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)
    
    # Relationship
    donor = db.relationship('User', backref='appointments')

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    title = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(20))  # info, warning, success, error
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Donation Camps
class Camp(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    camp_name = db.Column(db.String(150), nullable=False)
    location = db.Column(db.Text, nullable=False)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    organizer = db.Column(db.String(120))
    contact_phone = db.Column(db.String(20))
    expected_donors = db.Column(db.Integer, default=0)
    actual_donors = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='scheduled')  # scheduled, ongoing, completed

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        user_type = request.form['user_type']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return render_template('register.html')
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            user_type=user_type
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))
    
# change password route
@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # Verify current password
        if not check_password_hash(current_user.password_hash, current_password):
            flash('Current password is incorrect')
            return render_template('change_password.html')
        
        # Check if new passwords match
        if new_password != confirm_password:
            flash('New passwords do not match')
            return render_template('change_password.html')
        
        # Check password length
        if len(new_password) < 6:
            flash('New password must be at least 6 characters long')
            return render_template('change_password.html')
        
        # Update password
        current_user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        flash('Password changed successfully!')
        return redirect(url_for('dashboard'))
    
    return render_template('change_password.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.user_type == 'admin':
        return admin_dashboard()
    elif current_user.user_type == 'donor':
        return donor_dashboard()
    elif current_user.user_type == 'recipient':
        return recipient_dashboard()
    else:
        return redirect(url_for('index'))

def admin_dashboard():
    total_donors = User.query.filter_by(user_type='donor').count()
    total_recipients = User.query.filter_by(user_type='recipient').count()
    total_blood_units = db.session.query(db.func.sum(BloodStock.units_available)).scalar() or 0
    pending_requests = BloodRequest.query.filter_by(status='pending').count()
    
    # Appointment statistics
    total_appointments = DonationAppointment.query.count()
    scheduled_appointments = DonationAppointment.query.filter_by(status='scheduled').count()
    completed_appointments = DonationAppointment.query.filter_by(status='completed').count()
    cancelled_appointments = DonationAppointment.query.filter_by(status='cancelled').count()
    
    # Get unread notifications for admin
    unread_notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).order_by(Notification.created_at.desc()).limit(5).all()
    total_unread_notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    
    stats = {
        'total_donors': total_donors,
        'total_recipients': total_recipients,
        'total_blood_units': total_blood_units,
        'pending_requests': pending_requests,
        'total_appointments': total_appointments,
        'scheduled_appointments': scheduled_appointments,
        'completed_appointments': completed_appointments,
        'cancelled_appointments': cancelled_appointments,
        'unread_notifications': total_unread_notifications
    }
    
    recent_requests = BloodRequest.query.order_by(BloodRequest.request_date.desc()).limit(5).all()
    recent_appointments = DonationAppointment.query.order_by(DonationAppointment.appointment_date.desc()).limit(5).all()
    blood_stock = BloodStock.query.filter_by(status='available').all()
    
    return render_template('admin_dashboard.html', stats=stats, recent_requests=recent_requests, recent_appointments=recent_appointments, blood_stock=blood_stock, unread_notifications=unread_notifications)

def donor_dashboard():
    appointments = DonationAppointment.query.filter_by(donor_id=current_user.id).order_by(DonationAppointment.appointment_date.desc()).limit(5).all()
    donation_history = BloodStock.query.filter_by(donor_id=current_user.id).all()
    
    # Get unread notifications for donor
    unread_notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).order_by(Notification.created_at.desc()).limit(5).all()
    total_unread_notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    
    return render_template('donor_dashboard.html', appointments=appointments, donation_history=donation_history, unread_notifications=unread_notifications, total_unread_notifications=total_unread_notifications)

def recipient_dashboard():
    my_requests = BloodRequest.query.filter_by(requester_id=current_user.id).order_by(BloodRequest.request_date.desc()).all()
    available_blood = BloodStock.query.filter_by(status='available').all()
    
    return render_template('recipient_dashboard.html', my_requests=my_requests, available_blood=available_blood)

@app.route('/recipient/requests/<int:request_id>/cancel', methods=['POST'])
@login_required
def cancel_my_request(request_id):
    if current_user.user_type != 'recipient':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    req = BloodRequest.query.get_or_404(request_id)
    if req.requester_id != current_user.id:
        return jsonify({'success': False, 'message': 'Not your request'}), 403
    try:
        req.status = 'cancelled'
        db.session.commit()
        return jsonify({'success': True})
    except Exception:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to cancel request'}), 500

# Admin routes
@app.route('/admin/donors')
@login_required
def admin_donors():
    if current_user.user_type != 'admin':
        return redirect(url_for('dashboard'))
    
    donors = User.query.filter_by(user_type='donor').all()
    return render_template('admin_donors.html', donors=donors)

@app.route('/admin/donors/add', methods=['GET', 'POST'])
@login_required
def admin_add_donor():
    if current_user.user_type != 'admin':
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        full_name = request.form.get('full_name')
        phone = request.form.get('phone')
        blood_group = request.form.get('blood_group')
        age = request.form.get('age')
        weight = request.form.get('weight')
        last_donation = request.form.get('last_donation')
        address = request.form.get('address')
        medical_history = request.form.get('medical_history')

        if not username or not email or not password:
            flash('Username, email, and password are required')
            return render_template('admin_add_donor.html')
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return render_template('admin_add_donor.html')
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return render_template('admin_add_donor.html')

        donor = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            user_type='donor',
            full_name=full_name,
            phone=phone,
            blood_group=blood_group,
            age=int(age) if age else None,
            weight=float(weight) if weight else None,
            address=address,
            medical_history=medical_history
        )
        if last_donation:
            try:
                donor.last_donation = datetime.strptime(last_donation, '%Y-%m-%d')
            except ValueError:
                flash('Invalid last donation date. Use YYYY-MM-DD')
                return render_template('admin_add_donor.html')

        try:
            db.session.add(donor)
            db.session.commit()
            flash('Donor added successfully!')
            return redirect(url_for('admin_donors'))
        except Exception:
            db.session.rollback()
            flash('Failed to add donor')
            return render_template('admin_add_donor.html')

    return render_template('admin_add_donor.html')

@app.route('/admin/donors/<int:donor_id>/edit', methods=['GET', 'POST'])
@login_required
def admin_edit_donor(donor_id):
    if current_user.user_type != 'admin':
        return redirect(url_for('dashboard'))
    donor = User.query.filter_by(id=donor_id, user_type='donor').first_or_404()
    if request.method == 'POST':
        donor.full_name = request.form.get('full_name')
        donor.username = request.form.get('username') or donor.username
        donor.email = request.form.get('email') or donor.email
        donor.phone = request.form.get('phone')
        donor.blood_group = request.form.get('blood_group')
        donor.age = int(request.form.get('age')) if request.form.get('age') else None
        donor.weight = float(request.form.get('weight')) if request.form.get('weight') else None
        last_donation_str = request.form.get('last_donation')
        if last_donation_str:
            try:
                donor.last_donation = datetime.strptime(last_donation_str, '%Y-%m-%d')
            except ValueError:
                flash('Invalid last donation date format. Use YYYY-MM-DD')
                return render_template('admin_edit_donor.html', donor=donor)
        else:
            donor.last_donation = None
        donor.address = request.form.get('address')
        donor.medical_history = request.form.get('medical_history')
        try:
            db.session.commit()
            flash('Donor updated successfully!')
            return redirect(url_for('admin_donors'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to update donor.')
    return render_template('admin_edit_donor.html', donor=donor)

@app.route('/admin/donors/<int:donor_id>/delete', methods=['POST'])
@login_required
def admin_delete_donor(donor_id):
    if current_user.user_type != 'admin':
        return redirect(url_for('dashboard'))
    donor = User.query.filter_by(id=donor_id, user_type='donor').first_or_404()
    try:
        # Optional: delete related data if desired
        DonationAppointment.query.filter_by(donor_id=donor.id).delete()
        BloodStock.query.filter_by(donor_id=donor.id).delete()
        db.session.delete(donor)
        db.session.commit()
        flash('Donor deleted successfully!')
    except Exception:
        db.session.rollback()
        flash('Failed to delete donor.')
    return redirect(url_for('admin_donors'))

@app.route('/admin/donors/<int:donor_id>/details')
@login_required
def admin_donor_details(donor_id):
    if current_user.user_type != 'admin':
        return redirect(url_for('dashboard'))
    donor = User.query.filter_by(id=donor_id, user_type='donor').first_or_404()
    data = {
        'id': donor.id,
        'username': donor.username,
        'full_name': donor.full_name or '',
        'email': donor.email,
        'phone': donor.phone or '',
        'blood_group': donor.blood_group or '',
        'age': donor.age or '',
        'weight': donor.weight or '',
        'last_donation': donor.last_donation.strftime('%Y-%m-%d') if donor.last_donation else '',
        'address': donor.address or '',
        'medical_history': donor.medical_history or ''
    }
    return jsonify(data)

@app.route('/admin/blood-stock')
@login_required
def admin_blood_stock():
    if current_user.user_type != 'admin':
        return redirect(url_for('dashboard'))
    
    blood_stock = BloodStock.query.all()
    today = datetime.utcnow().date()
    return render_template('admin_blood_stock.html', blood_stock=blood_stock, today=today)

@app.route('/admin/blood-stock/save', methods=['POST'])
@login_required
def admin_save_blood_stock():
    if current_user.user_type != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    data = request.get_json() or {}
    stock_id = data.get('id')
    blood_group = data.get('blood_group')
    units_available = data.get('units_available')
    collection_date = data.get('collection_date')
    expiry_date = data.get('expiry_date')
    donor_id = data.get('donor_id')
    status = data.get('status') or 'available'

    if not blood_group or not units_available or not collection_date or not expiry_date:
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400

    try:
        units_available = int(units_available)
        collection_dt = datetime.strptime(collection_date, '%Y-%m-%d')
        expiry_dt = datetime.strptime(expiry_date, '%Y-%m-%d')
        donor_id_val = int(donor_id) if donor_id else None
    except Exception:
        return jsonify({'success': False, 'message': 'Invalid data format'}), 400

    try:
        if stock_id:
            stock = BloodStock.query.get(int(stock_id))
            if not stock:
                return jsonify({'success': False, 'message': 'Stock not found'}), 404
        else:
            stock = BloodStock()

        stock.blood_group = blood_group
        stock.units_available = units_available
        stock.collection_date = collection_dt
        stock.expiry_date = expiry_dt
        stock.donor_id = donor_id_val
        stock.status = status

        db.session.add(stock)
        db.session.commit()
        return jsonify({'success': True, 'id': stock.id})
    except Exception:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to save stock'}), 500

@app.route('/admin/blood-stock/<int:stock_id>/delete', methods=['POST'])
@login_required
def admin_delete_blood_stock(stock_id):
    if current_user.user_type != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    stock = BloodStock.query.get_or_404(stock_id)
    try:
        db.session.delete(stock)
        db.session.commit()
        return jsonify({'success': True})
    except Exception:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to delete stock'}), 500

@app.route('/admin/requests')
@login_required
def admin_requests():
    if current_user.user_type != 'admin':
        return redirect(url_for('dashboard'))
    
    requests = BloodRequest.query.all()
    return render_template('admin_requests.html', requests=requests)

@app.route('/admin/requests/<int:request_id>/approve', methods=['POST'])
@login_required
def admin_approve_request(request_id):
    if current_user.user_type != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    req = BloodRequest.query.get_or_404(request_id)
    try:
        req.status = 'approved'
        db.session.commit()
        return jsonify({'success': True})
    except Exception:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to approve request'}), 500

@app.route('/admin/requests/<int:request_id>/deny', methods=['POST'])
@login_required
def admin_deny_request(request_id):
    if current_user.user_type != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    req = BloodRequest.query.get_or_404(request_id)
    try:
        req.status = 'denied'
        db.session.commit()
        return jsonify({'success': True})
    except Exception:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to deny request'}), 500

@app.route('/admin/requests/bulk-approve', methods=['POST'])
@login_required
def admin_bulk_approve_requests():
    if current_user.user_type != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    data = request.get_json() or {}
    ids = data.get('ids') or []
    if not isinstance(ids, list) or not ids:
        return jsonify({'success': False, 'message': 'No request IDs provided'}), 400
    try:
        updated = BloodRequest.query.filter(BloodRequest.id.in_(ids)).update({'status': 'approved'}, synchronize_session=False)
        db.session.commit()
        return jsonify({'success': True, 'updated': updated})
    except Exception:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to bulk approve'}), 500

@app.route('/admin/appointments')
@login_required
def admin_appointments():
    if current_user.user_type != 'admin':
        return redirect(url_for('dashboard'))
    
    appointments = DonationAppointment.query.order_by(DonationAppointment.appointment_date.desc()).all()
    return render_template('admin_appointments.html', appointments=appointments)

@app.route('/admin/appointments/<int:appointment_id>/complete', methods=['POST'])
@login_required
def admin_complete_appointment(appointment_id):
    if current_user.user_type != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    appt = DonationAppointment.query.get_or_404(appointment_id)
    try:
        appt.status = 'completed'
        db.session.commit()
        return jsonify({'success': True})
    except Exception:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to complete appointment'}), 500

@app.route('/admin/appointments/<int:appointment_id>/cancel', methods=['POST'])
@login_required
def admin_cancel_appointment(appointment_id):
    if current_user.user_type != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    appt = DonationAppointment.query.get_or_404(appointment_id)
    try:
        appt.status = 'cancelled'
        db.session.commit()
        return jsonify({'success': True})
    except Exception:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to cancel appointment'}), 500

# Notification routes
@app.route('/admin/notifications')
@login_required
def admin_notifications():
    if current_user.user_type != 'admin':
        return redirect(url_for('dashboard'))
    
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return render_template('admin_notifications.html', notifications=notifications)

@app.route('/admin/notifications/<int:notification_id>/mark-read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    if current_user.user_type != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    notification = Notification.query.filter_by(id=notification_id, user_id=current_user.id).first()
    if not notification:
        return jsonify({'success': False, 'message': 'Notification not found'}), 404
    
    try:
        notification.is_read = True
        db.session.commit()
        return jsonify({'success': True})
    except Exception:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to mark notification as read'}), 500

@app.route('/admin/notifications/mark-all-read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    if current_user.user_type != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    try:
        Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
        db.session.commit()
        return jsonify({'success': True})
    except Exception:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to mark all notifications as read'}), 500

# Donor notification routes
@app.route('/donor/notifications')
@login_required
def donor_notifications():
    if current_user.user_type != 'donor':
        return redirect(url_for('dashboard'))
    
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return render_template('donor_notifications.html', notifications=notifications)

@app.route('/donor/notifications/<int:notification_id>/mark-read', methods=['POST'])
@login_required
def donor_mark_notification_read(notification_id):
    if current_user.user_type != 'donor':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    notification = Notification.query.filter_by(id=notification_id, user_id=current_user.id).first()
    if not notification:
        return jsonify({'success': False, 'message': 'Notification not found'}), 404
    
    try:
        notification.is_read = True
        db.session.commit()
        return jsonify({'success': True})
    except Exception:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to mark notification as read'}), 500

@app.route('/donor/notifications/mark-all-read', methods=['POST'])
@login_required
def donor_mark_all_notifications_read():
    if current_user.user_type != 'donor':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    try:
        Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
        db.session.commit()
        return jsonify({'success': True})
    except Exception:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to mark all notifications as read'}), 500

@app.route('/admin/reports')
@login_required
def admin_reports():
    if current_user.user_type != 'admin':
        return redirect(url_for('dashboard'))
    stats = {
        'total_donors': User.query.filter_by(user_type='donor').count(),
        'total_recipients': User.query.filter_by(user_type='recipient').count(),
        'total_blood_units': db.session.query(db.func.sum(BloodStock.units_available)).scalar() or 0,
        'pending_requests': BloodRequest.query.filter_by(status='pending').count(),
    }
    return render_template('admin_reports.html', stats=stats)

# Admin: Camps
@app.route('/admin/camps')
@login_required
def admin_camps():
    if current_user.user_type != 'admin':
        return redirect(url_for('dashboard'))
    camps = Camp.query.order_by(Camp.start_date.desc()).all()
    return render_template('admin_camps.html', camps=camps)

@app.route('/admin/camps/add', methods=['GET', 'POST'])
@login_required
def add_camp():
    if current_user.user_type != 'admin':
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        camp_name = request.form.get('camp_name', '').strip()
        location = request.form.get('location', '').strip()
        organizer = request.form.get('organizer', '').strip()
        contact_phone = request.form.get('contact_phone', '').strip()
        expected_donors = request.form.get('expected_donors', '0').strip()
        start_date_str = request.form.get('start_date')
        end_date_str = request.form.get('end_date')

        errors = []
        if not camp_name:
            errors.append('Camp name is required')
        if not location:
            errors.append('Location is required')
        try:
            expected_donors_val = int(expected_donors or '0')
            if expected_donors_val < 0:
                errors.append('Expected donors cannot be negative')
        except Exception:
            errors.append('Expected donors must be a number')
            expected_donors_val = 0
        try:
            start_dt = datetime.strptime(start_date_str, '%Y-%m-%dT%H:%M') if start_date_str else None
            end_dt = datetime.strptime(end_date_str, '%Y-%m-%dT%H:%M') if end_date_str else None
        except Exception:
            start_dt = end_dt = None
        if not start_dt or not end_dt:
            errors.append('Start and End date/time are required')
        elif end_dt <= start_dt:
            errors.append('End date must be after start date')

        if errors:
            for e in errors:
                flash(e)
            return render_template('add_camp.html')

        try:
            camp = Camp(
                camp_name=camp_name,
                location=location,
                organizer=organizer,
                contact_phone=contact_phone,
                expected_donors=expected_donors_val,
                start_date=start_dt,
                end_date=end_dt,
                status='scheduled'
            )
            db.session.add(camp)
            db.session.commit()
            flash('Camp added successfully!')
            return redirect(url_for('admin_camps'))
        except Exception:
            db.session.rollback()
            flash('Failed to add camp')
            return render_template('add_camp.html')

    return render_template('add_camp.html')

# Admin: Blood Units view (mapped to existing BloodStock)
@app.route('/admin/blood-units')
@login_required
def admin_blood_units():
    if current_user.user_type != 'admin':
        return redirect(url_for('dashboard'))
    # Map BloodStock to the template's expected fields
    stocks = BloodStock.query.all()
    # Build lightweight objects with expected attributes
    class UnitView:
        pass
    blood_units = []
    for s in stocks:
        u = UnitView()
        u.id = s.id
        u.barcode = f"BB{s.id:06d}"
        u.blood_group = s.blood_group
        u.units = s.units_available
        u.collection_date = s.collection_date
        u.expiry_date = s.expiry_date
        u.donor_id = s.donor_id
        u.collection_center = 'Main Center'
        u.status = s.status
        u.donor = User.query.get(s.donor_id) if s.donor_id else None
        blood_units.append(u)
    today = datetime.utcnow().date()
    return render_template('admin_blood_units.html', blood_units=blood_units, today=today)

@app.route('/admin/camps/<int:camp_id>/details')
@login_required
def admin_camp_details(camp_id):
    if current_user.user_type != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    camp = Camp.query.get_or_404(camp_id)
    data = {
        'id': camp.id,
        'camp_name': camp.camp_name,
        'location': camp.location,
        'organizer': camp.organizer or '',
        'contact_phone': camp.contact_phone or '',
        'expected_donors': camp.expected_donors,
        'actual_donors': camp.actual_donors,
        'status': camp.status,
        'start_date': camp.start_date.strftime('%Y-%m-%d %H:%M') if camp.start_date else '',
        'end_date': camp.end_date.strftime('%Y-%m-%d %H:%M') if camp.end_date else ''
    }
    return jsonify(data)

@app.route('/admin/camps/<int:camp_id>/edit', methods=['POST'])
@login_required
def admin_edit_camp(camp_id):
    if current_user.user_type != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    camp = Camp.query.get_or_404(camp_id)
    data = request.get_json() or {}
    try:
        camp.camp_name = data.get('camp_name', camp.camp_name)
        camp.location = data.get('location', camp.location)
        camp.organizer = data.get('organizer', camp.organizer)
        camp.contact_phone = data.get('contact_phone', camp.contact_phone)
        if 'expected_donors' in data:
            camp.expected_donors = int(data.get('expected_donors') or 0)
        if 'actual_donors' in data:
            camp.actual_donors = int(data.get('actual_donors') or 0)
        if 'status' in data:
            camp.status = data.get('status') or camp.status
        if 'start_date' in data and data['start_date']:
            camp.start_date = datetime.strptime(data['start_date'], '%Y-%m-%dT%H:%M')
        if 'end_date' in data and data['end_date']:
            camp.end_date = datetime.strptime(data['end_date'], '%Y-%m-%dT%H:%M')
        db.session.commit()
        return jsonify({'success': True})
    except Exception:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to update camp'}), 500

@app.route('/admin/camps/<int:camp_id>/delete', methods=['POST'])
@login_required
def admin_delete_camp(camp_id):
    if current_user.user_type != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    camp = Camp.query.get_or_404(camp_id)
    try:
        db.session.delete(camp)
        db.session.commit()
        return jsonify({'success': True})
    except Exception:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to delete camp'}), 500

# Blood units API (wrappers over BloodStock)
@app.route('/admin/blood-units/<int:unit_id>/details')
@login_required
def admin_blood_unit_details(unit_id):
    if current_user.user_type != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    s = BloodStock.query.get_or_404(unit_id)
    donor = User.query.get(s.donor_id) if s.donor_id else None
    data = {
        'id': s.id,
        'barcode': f"BB{s.id:06d}",
        'blood_group': s.blood_group,
        'units': s.units_available,
        'collection_date': s.collection_date.strftime('%Y-%m-%d') if s.collection_date else '',
        'expiry_date': s.expiry_date.strftime('%Y-%m-%d') if s.expiry_date else '',
        'donor_id': s.donor_id,
        'donor_name': (donor.full_name or donor.username) if donor else '',
        'status': s.status,
        'collection_center': 'Main Center'
    }
    return jsonify(data)

@app.route('/admin/blood-units/save', methods=['POST'])
@login_required
def admin_blood_units_save():
    if current_user.user_type != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    # Delegate to existing save logic expecting JSON payload
    return admin_save_blood_stock()

@app.route('/admin/blood-units/<int:unit_id>/delete', methods=['POST'])
@login_required
def admin_blood_units_delete(unit_id):
    if current_user.user_type != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    return admin_delete_blood_stock(unit_id)

def _csv_response(filename, header, rows):
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(header)
    writer.writerows(rows)
    output = si.getvalue()
    return app.response_class(
        output,
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename="{filename}"'
        }
    )

@app.route('/admin/reports/export/donors.csv')
@login_required
def export_donors_csv():
    if current_user.user_type != 'admin':
        return redirect(url_for('dashboard'))
    donors = User.query.filter_by(user_type='donor').all()
    header = ['ID', 'Username', 'Full Name', 'Email', 'Phone', 'Blood Group', 'Age', 'Weight', 'Last Donation', 'Address']
    rows = []
    for d in donors:
        rows.append([
            d.id,
            d.username,
            d.full_name or '',
            d.email,
            d.phone or '',
            d.blood_group or '',
            d.age or '',
            d.weight or '',
            d.last_donation.strftime('%Y-%m-%d') if d.last_donation else '',
            (d.address or '').replace('\n', ' ')
        ])
    return _csv_response('donors.csv', header, rows)

@app.route('/admin/reports/export/blood_stock.csv')
@login_required
def export_blood_stock_csv():
    if current_user.user_type != 'admin':
        return redirect(url_for('dashboard'))
    stocks = BloodStock.query.all()
    header = ['ID', 'Blood Group', 'Units Available', 'Status', 'Collection Date', 'Expiry Date', 'Donor ID']
    rows = []
    for s in stocks:
        rows.append([
            s.id,
            s.blood_group,
            s.units_available,
            s.status,
            s.collection_date.strftime('%Y-%m-%d') if s.collection_date else '',
            s.expiry_date.strftime('%Y-%m-%d') if s.expiry_date else '',
            s.donor_id or ''
        ])
    return _csv_response('blood_stock.csv', header, rows)

@app.route('/admin/reports/export/requests.csv')
@login_required
def export_requests_csv():
    if current_user.user_type != 'admin':
        return redirect(url_for('dashboard'))
    requests_q = BloodRequest.query.order_by(BloodRequest.request_date.desc()).all()
    header = ['ID', 'Requester ID', 'Blood Group', 'Units Needed', 'Urgency', 'Status', 'Patient Name', 'Hospital', 'Phone', 'Request Date']
    rows = []
    for r in requests_q:
        rows.append([
            r.id,
            r.requester_id,
            r.blood_group,
            r.units_needed,
            r.urgency_level,
            r.status,
            r.patient_name or '',
            r.hospital_name or '',
            r.contact_phone or '',
            r.request_date.strftime('%Y-%m-%d') if r.request_date else ''
        ])
    return _csv_response('requests.csv', header, rows)

# Public Camps
@app.route('/camps')
def camps():
    now = datetime.utcnow()
    upcoming = Camp.query.filter(Camp.end_date >= now).order_by(Camp.start_date.asc()).all()
    past = Camp.query.filter(Camp.end_date < now).order_by(Camp.start_date.desc()).limit(10).all()
    return render_template('camps.html', upcoming_camps=upcoming, past_camps=past, now=now)

@app.route('/api/camps')
def api_camps():
    now = datetime.utcnow()
    camps_q = Camp.query.filter(Camp.end_date >= now).order_by(Camp.start_date.asc()).all()
    data = []
    for c in camps_q:
        data.append({
            'id': c.id,
            'camp_name': c.camp_name,
            'location': c.location,
            'organizer': c.organizer or '',
            'contact_phone': c.contact_phone or '',
            'expected_donors': c.expected_donors,
            'actual_donors': c.actual_donors,
            'status': c.status,
            'start_date': c.start_date.strftime('%Y-%m-%d %H:%M'),
            'end_date': c.end_date.strftime('%Y-%m-%d %H:%M'),
        })
    return jsonify(data)

# Donor routes
@app.route('/donor/profile', methods=['GET', 'POST'])
@login_required
def donor_profile():
    if current_user.user_type != 'donor':
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        current_user.full_name = request.form['full_name']
        current_user.phone = request.form['phone']
        current_user.blood_group = request.form['blood_group']
        current_user.age = int(request.form['age'])
        current_user.weight = float(request.form['weight'])
        current_user.medical_history = request.form['medical_history']
        current_user.address = request.form['address']
        
        db.session.commit()
        flash('Profile updated successfully!')
        return redirect(url_for('donor_profile'))
    
    return render_template('donor_profile.html')

@app.route('/donor/book-appointment', methods=['GET', 'POST'])
@login_required
def book_appointment():
    if current_user.user_type != 'donor':
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        appointment_date = datetime.strptime(request.form['appointment_date'], '%Y-%m-%dT%H:%M')
        notes = request.form.get('notes', '')
        
        appointment = DonationAppointment(
            donor_id=current_user.id,
            appointment_date=appointment_date,
            notes=notes
        )
        
        db.session.add(appointment)
        db.session.commit()
        
        # Send notification to all admins about new appointment
        admins = User.query.filter_by(user_type='admin').all()
        for admin in admins:
            notification = Notification(
                user_id=admin.id,
                title='New Donation Appointment Booked',
                message=f'Donor {current_user.full_name or current_user.username} has booked an appointment for {appointment_date.strftime("%Y-%m-%d at %I:%M %p")}',
                notification_type='info'
            )
            db.session.add(notification)
        
        # Send confirmation notification to donor
        donor_notification = Notification(
            user_id=current_user.id,
            title='Appointment Booked Successfully',
            message=f'Your blood donation appointment has been confirmed for {appointment_date.strftime("%Y-%m-%d at %I:%M %p")}. Please arrive 15 minutes early.',
            notification_type='success'
        )
        db.session.add(donor_notification)
        
        db.session.commit()
        
        flash('Appointment booked successfully!')
        return redirect(url_for('dashboard'))
    
    return render_template('book_appointment.html')

@app.route('/donor/appointments/<int:appointment_id>/cancel', methods=['POST'])
@login_required
def cancel_appointment(appointment_id):
    if current_user.user_type != 'donor':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    appt = DonationAppointment.query.get_or_404(appointment_id)
    if appt.donor_id != current_user.id:
        return jsonify({'success': False, 'message': 'Not your appointment'}), 403
    try:
        appt.status = 'cancelled'
        
        # Send notification to admins about cancelled appointment
        admins = User.query.filter_by(user_type='admin').all()
        for admin in admins:
            notification = Notification(
                user_id=admin.id,
                title='Appointment Cancelled',
                message=f'Donor {current_user.full_name or current_user.username} has cancelled their appointment scheduled for {appt.appointment_date.strftime("%Y-%m-%d at %I:%M %p")}',
                notification_type='warning'
            )
            db.session.add(notification)
        
        # Send notification to donor
        donor_notification = Notification(
            user_id=current_user.id,
            title='Appointment Cancelled',
            message=f'Your appointment for {appt.appointment_date.strftime("%Y-%m-%d at %I:%M %p")} has been cancelled successfully.',
            notification_type='info'
        )
        db.session.add(donor_notification)
        
        db.session.commit()
        return jsonify({'success': True})
    except Exception:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to cancel appointment'}), 500

@app.route('/donor/eligibility')
@login_required
def donor_eligibility():
    if current_user.user_type != 'donor':
        return jsonify({'eligible': False, 'reasons': ['Unauthorized']}), 403
    reasons = []
    eligible = True
    # Age 18-65
    if not current_user.age or current_user.age < 18 or current_user.age > 65:
        eligible = False
        reasons.append('Age must be between 18 and 65 years')
    # Weight >= 50
    if not current_user.weight or current_user.weight < 50:
        eligible = False
        reasons.append('Weight must be at least 50 kg')
    # Last donation >= 56 days
    if current_user.last_donation:
        days_since = (datetime.utcnow() - current_user.last_donation).days
        if days_since < 56:
            eligible = False
            reasons.append('Wait at least 56 days between donations')
    # Basic fields present
    if not current_user.blood_group:
        eligible = False
        reasons.append('Blood group not set')
    if not current_user.full_name or not current_user.phone or not current_user.address:
        eligible = False
        reasons.append('Complete profile (name, phone, address)')
    return jsonify({'eligible': eligible, 'reasons': reasons})

# Recipient routes
@app.route('/recipient/request-blood', methods=['GET', 'POST'])
@login_required
def request_blood():
    if current_user.user_type != 'recipient':
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        blood_group = request.form.get('blood_group', '').strip()
        units_needed_raw = request.form.get('units_needed', '').strip()
        urgency_level = request.form.get('urgency_level', '').strip()
        patient_name = request.form.get('patient_name', '').strip()
        hospital_name = request.form.get('hospital_name', '').strip()
        contact_phone = request.form.get('contact_phone', '').strip()

        # Basic validation
        errors = []
        if not blood_group:
            errors.append('Blood group is required')
        try:
            units_needed = int(units_needed_raw)
            if units_needed < 1 or units_needed > 10:
                errors.append('Units needed must be between 1 and 10')
        except Exception:
            errors.append('Units needed must be a number')
            units_needed = None
        if not urgency_level:
            urgency_level = 'emergency' if request.form.get('confirm_urgent') else 'low'
        if not patient_name:
            errors.append('Patient name is required')
        if not hospital_name:
            errors.append('Hospital name is required')
        if not contact_phone:
            errors.append('Contact phone is required')

        if errors:
            for e in errors:
                flash(e)
            return render_template('request_blood.html')
        
        blood_request = BloodRequest(
            requester_id=current_user.id,
            blood_group=blood_group,
            units_needed=units_needed,
            urgency_level=urgency_level,
            patient_name=patient_name,
            hospital_name=hospital_name,
            contact_phone=contact_phone
        )
        
        db.session.add(blood_request)
        db.session.commit()
        
        flash('Blood request submitted successfully!')
        return redirect(url_for('dashboard'))
    
    return render_template('request_blood.html')

@app.route('/search-blood')
def search_blood():
    blood_group = request.args.get('blood_group', '')
    location = request.args.get('location', '')
    
    query = BloodStock.query.filter_by(status='available')
    if blood_group:
        query = query.filter_by(blood_group=blood_group)
    
    available_blood = query.all()
    today = datetime.utcnow().date()
    return render_template('search_blood.html', available_blood=available_blood, blood_group=blood_group, location=location, today=today)

# Public: Blood stock details
@app.route('/blood-stock/<int:stock_id>/details')
def blood_stock_details(stock_id):
    stock = BloodStock.query.get_or_404(stock_id)
    donor = User.query.get(stock.donor_id) if stock.donor_id else None
    today = datetime.utcnow().date()
    days_to_expiry = None
    if stock.expiry_date:
        try:
            days_to_expiry = (stock.expiry_date.date() - today).days
        except Exception:
            days_to_expiry = None
    data = {
        'id': stock.id,
        'blood_group': stock.blood_group,
        'units_available': stock.units_available,
        'status': stock.status,
        'collection_date': stock.collection_date.strftime('%Y-%m-%d') if stock.collection_date else '',
        'expiry_date': stock.expiry_date.strftime('%Y-%m-%d') if stock.expiry_date else '',
        'days_to_expiry': days_to_expiry,
        'donor': {
            'id': donor.id,
            'name': donor.full_name or donor.username,
            'blood_group': donor.blood_group
        } if donor else None
    }
    return jsonify(data)

# Recipient emergency request
@app.route('/recipient/emergency-request', methods=['POST'])
@login_required
def recipient_emergency_request():
    if current_user.user_type != 'recipient':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    data = request.get_json() or {}
    blood_group = data.get('blood_group')
    units_needed = data.get('units_needed', 1)
    try:
        units_needed = int(units_needed)
    except Exception:
        return jsonify({'success': False, 'message': 'Invalid units'}), 400
    if not blood_group:
        return jsonify({'success': False, 'message': 'Blood group is required'}), 400
    try:
        blood_request = BloodRequest(
            requester_id=current_user.id,
            blood_group=blood_group,
            units_needed=units_needed,
            urgency_level='emergency',
            patient_name=current_user.patient_name or '',
            hospital_name=current_user.hospital_name or '',
            contact_phone=current_user.phone or ''
        )
        db.session.add(blood_request)
        db.session.commit()
        return jsonify({'success': True, 'request_id': blood_request.id})
    except Exception:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to create emergency request'}), 500

@app.route('/admin/requests/<int:request_id>/details')
@login_required
def admin_request_details(request_id):
    if current_user.user_type != 'admin':
        return redirect(url_for('dashboard'))
    req = BloodRequest.query.get_or_404(request_id)
    requester = User.query.get(req.requester_id)
    data = {
        'id': req.id,
        'blood_group': req.blood_group,
        'units_needed': req.units_needed,
        'urgency_level': req.urgency_level,
        'status': req.status,
        'patient_name': req.patient_name or '',
        'hospital_name': req.hospital_name or '',
        'contact_phone': req.contact_phone or '',
        'request_date': req.request_date.strftime('%Y-%m-%d %H:%M') if req.request_date else '',
        'admin_notes': req.admin_notes or '',
        'requester_name': requester.full_name or requester.username if requester else 'Unknown',
        'requester_email': requester.email if requester else ''
    }
    return jsonify(data)

@app.route('/search-blood/export.csv')
def export_search_blood_csv():
    blood_group = request.args.get('blood_group', '')
    location = request.args.get('location', '')
    query = BloodStock.query.filter_by(status='available')
    if blood_group:
        query = query.filter_by(blood_group=blood_group)
    results = query.all()
    header = ['ID', 'Blood Group', 'Units Available', 'Status', 'Collection Date', 'Expiry Date', 'Donor ID']
    rows = []
    for b in results:
        rows.append([
            b.id,
            b.blood_group,
            b.units_available,
            b.status,
            b.collection_date.strftime('%Y-%m-%d') if b.collection_date else '',
            b.expiry_date.strftime('%Y-%m-%d') if b.expiry_date else '',
            b.donor_id or ''
        ])
    return _csv_response('search_results.csv', header, rows)

# API routes
@app.route('/api/blood-availability')
def api_blood_availability():
    blood_groups = ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-']
    availability = {}
    
    for bg in blood_groups:
        total_units = db.session.query(db.func.sum(BloodStock.units_available)).filter_by(blood_group=bg, status='available').scalar() or 0
        availability[bg] = total_units
    
    return jsonify(availability)

# ---- automatic table creation ----
with app.app_context():
    try:
        db.create_all()
        print("✅ Tables created successfully on Render!")
    except Exception as e:
        print("❌ Error creating tables:", e)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)