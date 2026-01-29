# Mini-SIEM - Security Information and Event Management System

A lightweight Security Information and Event Management (SIEM) system built with Flask and MySQL, designed for monitoring, alerting, and threat detection.

## Quick Start

👉 **Start here:** See [SETUP_GUIDE.md](SETUP_GUIDE.md) for complete setup, installation, and usage instructions.

## Documentation

- **[SETUP_GUIDE.md](SETUP_GUIDE.md)** - Complete installation, configuration, and user guide
  - System requirements and environment setup
  - Database initialization
  - Running the application
  - Default login credentials
  - Feature overview
  - Common tasks and troubleshooting

- **[DATABASE_GUIDE.md](DATABASE_GUIDE.md)** - Complete database documentation
  - Database schema for all 7 tables
  - Setup and maintenance procedures
  - User, alert, and rule management
  - Backup and restore procedures
  - Performance tuning
  - Common issues and solutions

## Key Features

- 🔐 Role-based user authentication (Admin/Analyst)
- 📊 Real-time security dashboard
- 🚨 Alert management and notifications
- 📝 Log collection and analysis
- 🎯 Detection rules engine
- 👥 User management system
- ⚙️ System settings and monitoring

## Project Structure

```
mini-siem/
├── app.py                    # Main Flask application
├── auth.py                   # Authentication module
├── config.py                 # Configuration settings
├── db.py                     # Database connection
├── detection_engine.py       # Alert/anomaly detection
├── models/
│   └── user_model.py         # User data model
├── templates/                # HTML templates
│   ├── dashboard.html
│   ├── alerts.html
│   ├── logs.html
│   ├── users.html
│   ├── rules.html
│   ├── settings.html
│   ├── add_rule.html
│   ├── edit_user.html
│   └── login.html
├── logs_generator/
│   └── send_logs.py          # Test log generator
├── DATABASE_SETUP.sql        # Complete database initialization script
├── SETUP_GUIDE.md            # Complete setup guide
└── DATABASE_GUIDE.md         # Database documentation
```

## System Requirements

- Python 3.8+
- MySQL 5.7+
- 512MB RAM minimum
- 1GB disk space minimum

## Getting Started

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure Database**
   - Update MySQL credentials in `config.py`
   - Run database setup: See [DATABASE_GUIDE.md](DATABASE_GUIDE.md)

3. **Run Application**
   ```bash
   python app.py
   ```

4. **Access Dashboard**
   - URL: `http://localhost:5000`
   - Default credentials: See [SETUP_GUIDE.md](SETUP_GUIDE.md)

## Support & Troubleshooting

For setup issues, database problems, or feature questions:
- See **[SETUP_GUIDE.md](SETUP_GUIDE.md)** - Troubleshooting section
- See **[DATABASE_GUIDE.md](DATABASE_GUIDE.md)** - Common issues and solutions

## Technology Stack

- **Framework:** Flask 3.1.2
- **Database:** MySQL
- **Authentication:** Flask-Login with werkzeug
- **Frontend:** HTML5/CSS3
- **Python:** 3.8+

---

For detailed setup instructions, see [SETUP_GUIDE.md](SETUP_GUIDE.md)
