# Mini-SIEM Setup & Quick Start Guide

## Overview

Mini-SIEM is an enterprise-grade Security Information and Event Management (SIEM) system with real-time threat detection, log analysis, and user management capabilities.

---

## System Requirements

- **Python**: 3.8 or higher
- **Database**: MySQL 5.7+
- **OS**: Windows, macOS, or Linux
- **RAM**: Minimum 2GB recommended
- **Disk Space**: 1GB+ for logs and data

---

## 1. Initial Setup

### Step 1: Python Environment Setup

```bash
# Navigate to project directory
cd C:\Users\gupta\OneDrive\Desktop\mini-siem

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate

# On macOS/Linux:
source venv/bin/activate
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

**Key Dependencies:**
- Flask 3.1.2 - Web framework
- Flask-Login 0.6.3 - Authentication
- mysql-connector-python - Database driver
- werkzeug - Password hashing & security

---

## 2. Database Setup

### Prerequisites

Ensure MySQL is installed and running. Update `config.py` with your credentials:

```python
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "your_password",  # Change this
    "database": "mini_siem"
}
```

### Create Database & Tables

Run the smart setup script (creates only missing tables):

```bash
mysql -u root -p mini_siem < DATABASE_SETUP_SMART.sql
```

When prompted, enter your MySQL password.

**What This Does:**
✅ Creates `rules` table (if missing)  
✅ Adds missing columns to `users` table  
✅ Preserves all existing data  
✅ Sets up proper indexes for performance

### Verify Setup

```bash
mysql -u root -p mini_siem

# In MySQL shell:
SHOW TABLES;
DESCRIBE users;
DESCRIBE rules;
DESCRIBE alerts;
DESCRIBE logs;
```

Expected output: 7 tables total (users, alerts, logs, rules, detection_rules, anomaly_alert_state, ip_baselines)

---

## 3. Running the Application

### Start Flask Server

```bash
python app.py
```

Expected output:
```
 * Running on http://127.0.0.1:5000
 * Debug mode: on
```

### Access the Dashboard

Open your browser and go to:
```
http://localhost:5000
```

---

## 4. Default Login Credentials

After first database setup, use these credentials:

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Admin (Full Access) |
| analyst | analyst123 | Analyst (View Only) |

**⚠️ IMPORTANT**: Change these passwords immediately after first login!

---

## 5. Main Features

### Dashboard (`/dashboard`)
- 📊 Real-time security metrics (8 KPIs)
- 🔴 Threat level indicator
- 📋 Recent activity feed
- ⚡ Quick access links

**Metrics Displayed:**
- Critical Alerts (24h)
- Open Alerts (in-progress)
- Total Alerts (24h)
- Active Rules
- Events per Hour
- Unique IPs (24h)
- Rules Triggered (24h)

### Alerts (`/alerts`)
- 🔍 Search and filter alerts by:
  - Severity (CRITICAL, HIGH, MEDIUM, LOW)
  - Status (OPEN, INVESTIGATING, RESOLVED)
  - Rule name, date range
- 📊 View total and open alert counts
- ✅ Mark alerts as resolved

### Logs (`/logs`)
- 📝 View all system logs (1000+)
- 🔍 Advanced filtering:
  - Log level (INFO, WARNING, ERROR, CRITICAL)
  - Source (system, detector, database)
  - IP address
  - Date range
- 💾 Search message content

### User Management (`/admin/users`) - Admin Only
- 👥 View all system users
- ➕ Add new users (admin or analyst)
- ✏️ Edit user role, password, status
- 🗑️ Delete users (with confirmation)
- 📊 See user creation date and last login

### Rules Management (`/admin/rules`) - Admin Only
- 📋 View all detection rules
- ➕ Add custom detection rules
- 🔄 Enable/disable rules
- ⚙️ Configure rule parameters

### System Settings (`/admin/settings`) - Admin Only
- 🖥️ System information & health
- 📊 Database connection status
- 💚 Health check (all components)
- 🗑️ Data management (cleanup old logs/alerts)

---

## 6. User Roles

### Admin Role
- Full access to all features
- Can manage users
- Can create/modify detection rules
- Can access system settings
- Can clean historical data

### Analyst Role
- View-only access to:
  - Dashboard metrics
  - Alerts and logs
  - Detection rules
- Cannot modify any data
- Cannot manage users

---

## 7. Common Tasks

### Add a New User

1. Login as admin
2. Go to Dashboard → Admin Panel → User Management
3. Click "+ Add New User"
4. Fill in username, password, and role
5. Click "Create User"

### Create a Custom Detection Rule

1. Login as admin
2. Go to Dashboard → Admin Panel → Rule Management
3. Click "+ Add Rule"
4. Configure rule parameters:
   - Rule name
   - Log field to monitor
   - Match type (contains, equals, regex)
   - Threshold and time window
   - Severity level
5. Click "Add Rule"

### Filter Alerts by Date Range

1. Go to Alerts page
2. Click "Apply Filters" under filter section
3. Set "From Date" and "To Date"
4. Select severity and status if needed
5. Click "Apply Filters"

### Clean Old Data

1. Login as admin
2. Go to Dashboard → Admin Panel → System Settings
3. In "Data Management" section:
   - Set number of days to keep
   - Click "Delete Old Logs" or "Delete Old Alerts"
4. Confirm the deletion

---

## 8. Troubleshooting

### Issue: Database Connection Error
```
Error: 2003 - Can't connect to MySQL server
```
**Solution:**
- Verify MySQL is running
- Check credentials in `config.py`
- Ensure database "mini_siem" exists
- Verify firewall isn't blocking port 3306

### Issue: No Logs Showing
```
Empty logs table
```
**Solution:**
- Check if logs_generator worker is running
- Verify detection_engine is generating logs
- Check database has write permissions

### Issue: User Management Shows 404
```
The requested URL was not found
```
**Solution:**
- Ensure you're logged in as admin
- Check database has "users" table
- Run DATABASE_SETUP_SMART.sql again

### Issue: Login Failed
```
Invalid credentials
```
**Solution:**
- Verify username is correct
- Check password (case-sensitive)
- Ensure user account is active (`is_active = 1`)

---

## 9. Database Schema

### users table
```
- id (INT, Primary Key)
- username (VARCHAR 50, Unique)
- password_hash (VARCHAR 255)
- role (ENUM: 'admin', 'analyst')
- is_active (BOOLEAN)
- created_at (DATETIME)
- last_login (DATETIME, Nullable)
```

### alerts table
```
- id (INT, Primary Key)
- rule_name (VARCHAR 100)
- severity (ENUM: CRITICAL, HIGH, MEDIUM, LOW)
- status (ENUM: OPEN, INVESTIGATING, RESOLVED)
- log_id (INT)
- created_time (DATETIME)
- message (TEXT)
```

### logs table
```
- id (INT, Primary Key)
- source (VARCHAR 50)
- level (ENUM: INFO, WARNING, ERROR, CRITICAL)
- message (TEXT)
- ip_address (VARCHAR 45)
- log_time (DATETIME)
```

### rules table
```
- id (INT, Primary Key)
- name (VARCHAR 255, Unique)
- condition (TEXT)
- severity (ENUM: CRITICAL, HIGH, MEDIUM, LOW)
- is_active (BOOLEAN)
- created_at (DATETIME)
```

---

## 10. Configuration

All configuration is in `config.py`:

```python
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "YOUR_PASSWORD",
    "database": "Your_DB_Name"
}
```

### Modify Settings:
- Update `host` for remote MySQL servers
- Change `user` and `password` to match your MySQL credentials
- Change `database` name if needed

---

## 11. Performance Tips

- **Index Usage**: All tables have proper indexes for fast queries
- **Log Rotation**: Use "Clear Old Logs" in System Settings regularly
- **Database Maintenance**: Run MySQL OPTIMIZE TABLE periodically
- **Monitoring**: Check System Settings health dashboard regularly

---

## 12. Security Best Practices

✅ **DO:**
- Change default admin password immediately
- Use strong passwords (8+ characters)
- Regularly review user access
- Clean old data periodically
- Keep MySQL and Python updated

❌ **DON'T:**
- Share admin credentials
- Use weak passwords
- Disable authentication
- Expose database to internet
- Leave default passwords unchanged

---

## Support & Next Steps

For detailed technical information, see:
- `DATABASE_GUIDE.md` - Database setup and management
- `config.py` - Configuration reference
- Source code comments for implementation details

**Enjoy your Mini-SIEM!** 🛡️
