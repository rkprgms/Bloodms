# BloodConnect
# Blood Bank Management System
# Demo Link: https://bloodms.onrender.com
A comprehensive, modern, and user-friendly blood bank management system built with Python Flask, SQLite, HTML, CSS, and JavaScript, Jinja2 Template. This system provides complete functionality for managing blood donations, requests, and inventory with separate modules for administrators, donors, and recipients/patient.

## 🚀 Features

### 👥 User Management
- **Multi-role Authentication**: Separate login/signup for Admin, Donor, and Recipient
- **Secure Password Hashing**: Industry-standard security for user data
- **Profile Management**: Complete user profiles with medical history tracking

### 🩸 Donor Module
- **Donor Registration & Login**: Easy signup process with validation
- **Profile Management**: Personal info, medical history, blood group tracking
- **Eligibility Check**: Automated validation based on age, weight, and donation history
- **Appointment Booking**: Schedule donation appointments with availability checking
- **Donation History**: Track all past donations and their status
- **Notifications & Reminders**: Automated alerts for eligibility and appointments

### 🏥 Recipient/Patient Module
- **Blood Search**: Advanced search by blood group and location
- **Online Blood Requests**: Submit requests with urgency levels
- **Request Tracking**: Monitor request status in real-time
- **Emergency Contact**: 24/7 helpline for urgent requirements
- **Compatibility Check**: Blood group compatibility information

### ⚙️ Admin/Staff Module
- **Donor Database Management**: Complete donor information management
- **Blood Stock Management**: Add, update, delete blood units with expiry tracking
- **Request Management**: Approve/deny blood requests with admin notes
- **Inventory Tracking**: Real-time blood availability monitoring
- **Expiry Alerts**: Automated notifications for expiring blood units
- **Reporting System**: Generate comprehensive reports and analytics

### 🔍 General Features
- **Real-time Dashboard**: Live statistics and updates
- **Advanced Search**: Multi-criteria search functionality
- **Responsive Design**: Mobile-friendly interface for all devices
- **Modern UI/UX**: Beautiful, intuitive design with Bootstrap 5
- **Data Security**: Secure data handling and privacy protection
- **API Integration**: RESTful API for blood availability data

## 🛠️ Technology Stack

- **Backend**: Python Flask
- **Database**: SQLite
- **Frontend**: HTML5, CSS3, JavaScript (ES6+)
- **UI Framework**: Bootstrap 5
- **Icons**: Font Awesome 6
- **Authentication**: Flask-Login
- **Forms**: Flask-WTF with WTForms

## 📋 Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

## 🚀 Installation & Setup

### 1. Clone the Repository
```bash
git clone <repository-url>
cd new_blood
```

### 2. Create Virtual Environment
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Application
```bash
python app.py
```

### 5. Access the Application
Open your web browser and navigate to:
```
http://localhost:5000
```

## 📱 Usage Guide

### For Administrators
1. **Login** with admin credentials
2. **Dashboard**: View real-time statistics and recent requests
3. **Manage Donors**: Add, edit, or remove donor information
4. **Blood Stock**: Track inventory, add new units, monitor expiry
5. **Requests**: Approve or deny blood requests
6. **Reports**: Generate comprehensive analytics

### For Donors
1. **Register** as a donor with complete profile information
2. **Profile**: Update personal details and medical history
3. **Eligibility**: Check donation eligibility based on criteria
4. **Appointments**: Book donation appointments
5. **History**: View past donations and upcoming appointments

### For Recipients
1. **Register** as a recipient
2. **Search Blood**: Find available blood by group and location
3. **Request Blood**: Submit requests with urgency levels
4. **Track Requests**: Monitor request status
5. **Emergency**: Use emergency contact for urgent needs

## 🗄️ Database Schema

### Users Table
- User authentication and basic information
- Role-based access (admin, donor, recipient)
- Profile data and medical history

### Blood Stock Table
- Blood unit inventory management
- Expiry date tracking
- Donor association

### Blood Requests Table
- Request management and tracking
- Urgency levels and status updates
- Patient and hospital information

### Donation Appointments Table
- Appointment scheduling
- Status tracking
- Donor notifications

### Notifications Table
- System alerts and reminders
- User-specific notifications
- Read status tracking

## 🎨 UI/UX Features

- **Modern Design**: Clean, professional interface
- **Responsive Layout**: Works on all device sizes
- **Interactive Elements**: Smooth animations and transitions
- **Color-coded Status**: Easy-to-understand visual indicators
- **Accessibility**: WCAG compliant design
- **Mobile-First**: Optimized for mobile devices

## 🔒 Security Features

- **Password Hashing**: Secure password storage
- **Session Management**: Secure user sessions
- **Input Validation**: Server-side form validation
- **SQL Injection Protection**: Parameterized queries
- **XSS Protection**: Input sanitization

## 📊 Key Features in Detail

### Blood Group Compatibility
- Complete compatibility matrix
- Universal donor/recipient information
- Real-time compatibility checking

### Eligibility System
- Age verification (18-65 years)
- Weight requirements (minimum 50 kg)
- Donation interval checking (56 days minimum)
- Medical history validation

### Inventory Management
- Real-time stock levels
- Expiry date monitoring
- Low stock alerts
- Automated status updates

### Notification System
- Email notifications (ready for integration)
- Emergency alerts

## 🚀 Future Enhancements

- **SMS/Email Integration**: Real notification delivery
- **Mobile App**: Native mobile applications
- **Advanced Analytics**: Machine learning insights
- **Integration APIs**: Third-party system integration
- **Multi-language Support**: Internationalization
- **Advanced Reporting**: PDF/Excel export

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📞 Support

For support and questions:
- **Email**: support@bloodconnect.com
- **Phone**: +91-9876543210
- **Emergency**: Available 24/7

## 🙏 Acknowledgments

- Bootstrap for the UI framework
- Font Awesome for icons
- Flask community for excellent documentation
- All contributors and testers

---

**BloodConnect ** - Connecting lives through blood donation 💉❤️