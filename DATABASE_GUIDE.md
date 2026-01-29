# Mini-SIEM Database Setup & Management Guide

## Overview

This guide covers all database setup, configuration, and management tasks for Mini-SIEM.

---

## 1. Database Environment

### Database System: MySQL

Mini-SIEM uses MySQL 5.7+ with the following configuration:

**Location**: `config.py`

```python
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "YOUR_PASSWORD",
    "database": "Your_DB_Name"
}
```

**Python Driver**: `mysql-connector-python`

---

## 2. Initial Database Setup

### Prerequisites

- MySQL installed and running
- MySQL root or admin access
- Database credentials available

### Step 1: Create Database

```bash
mysql -u root -p
```

In MySQL shell:
```sql
CREATE DATABASE IF NOT EXISTS mini_siem;
USE mini_siem;
```

### Step 2: Run Smart Setup Script

The smart setup script only creates missing tables and columns - it preserves all existing data:

```bash
mysql -u root -p mini_siem < DATABASE_SETUP_SMART.sql
```

**What It Does:**
- ✅ Creates `rules` table (if not exists)
- ✅ Adds missing columns to `users` table (is_active, created_at, last_login)
- ✅ Adds performance indexes
- ✅ Sets proper collation (UTF-8)
- ✅ Preserves existing data

### Step 3: Verify Installation

```bash
mysql -u root -p mini_siem
```

Verify all tables exist:
```sql
SHOW TABLES;
```

Expected output (7 tables):
```
- alerts
- anomaly_alert_state
- detection_rules
- ip_baselines
- logs
- rules
- users
```

---

## 3. Database Schema

### Table: users

Stores system user accounts with authentication info.

```sql
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin', 'analyst') DEFAULT 'analyst',
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME NULL,
    INDEX idx_username (username),
    INDEX idx_role (role),
    INDEX idx_is_active (is_active)
);
```

**Fields:**
- `id`: Unique user identifier
- `username`: Login username (unique, required)
- `password_hash`: Hashed password (never stored plain-text)
- `role`: User role (admin = full access, analyst = read-only)
- `is_active`: Account status (1 = active, 0 = disabled)
- `created_at`: Account creation timestamp
- `last_login`: Last successful login timestamp

**Indexes:**
- `idx_username`: Speeds up username lookups during login
- `idx_role`: Enables quick admin-only queries
- `idx_is_active`: Filters active users efficiently

**Initial Users:**
```sql
INSERT INTO users (username, password_hash, role, is_active, created_at)
VALUES (
    'admin',
    'scrypt:32768:8:1$...',  -- Password: admin123
    'admin',
    1,
    NOW()
);
```

---

### Table: alerts

Stores security alerts triggered by detection rules.

```sql
CREATE TABLE alerts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    rule_name VARCHAR(255) NOT NULL,
    severity ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') DEFAULT 'LOW',
    status ENUM('OPEN', 'INVESTIGATING', 'RESOLVED') DEFAULT 'OPEN',
    created_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    message TEXT,
    ip_address VARCHAR(45),
    rule_id INT,
    INDEX idx_severity (severity),
    INDEX idx_status (status),
    INDEX idx_created_time (created_time)
);
```

**Fields:**
- `id`: Unique alert ID
- `rule_name`: Name of detection rule that triggered
- `severity`: Alert severity level (CRITICAL > HIGH > MEDIUM > LOW)
- `status`: Current alert status
- `created_time`: When alert was triggered
- `message`: Alert description/details
- `ip_address`: Source IP if applicable
- `rule_id`: Reference to detection_rules.id

**Indexes:**
- `idx_severity`: Query alerts by severity quickly
- `idx_status`: Filter by alert status (open/resolved)
- `idx_created_time`: Time-based queries efficient

**Typical Row Count:** 30-100+ (depends on detection rules)

---

### Table: logs

Stores all system, security, and application logs.

```sql
CREATE TABLE logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    log_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    source VARCHAR(255),
    level ENUM('INFO', 'WARNING', 'ERROR', 'CRITICAL') DEFAULT 'INFO',
    ip_address VARCHAR(45),
    message TEXT,
    INDEX idx_level (level),
    INDEX idx_source (source),
    INDEX idx_log_time (log_time)
);
```

**Fields:**
- `id`: Unique log ID
- `log_time`: Log timestamp
- `source`: Log source (system, detector, database, etc.)
- `level`: Log level (INFO, WARNING, ERROR, CRITICAL)
- `ip_address`: Source IP address
- `message`: Log message content

**Indexes:**
- `idx_level`: Query by log level
- `idx_source`: Filter by source
- `idx_log_time`: Time-range queries

**Typical Row Count:** 1000-10000+ (high volume)

---

### Table: rules

Stores custom detection rules created by admins.

```sql
CREATE TABLE rules (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL UNIQUE,
    condition TEXT NOT NULL,
    severity ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') DEFAULT 'MEDIUM',
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_name (name),
    INDEX idx_is_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

**Fields:**
- `id`: Unique rule ID
- `name`: Rule name (unique)
- `condition`: Rule condition/logic
- `severity`: Alert severity if rule triggers
- `is_active`: Whether rule is enabled
- `created_at`: When rule was created

**Indexes:**
- `idx_name`: Quick lookup by rule name
- `idx_is_active`: Query only active rules

**Typical Row Count:** 2-20+ (admin-created)

---

### Table: detection_rules

Pre-configured system detection rules (read-only).

```sql
CREATE TABLE detection_rules (
    id INT PRIMARY KEY AUTO_INCREMENT,
    rule_name VARCHAR(255) NOT NULL,
    log_field VARCHAR(100),
    match_type VARCHAR(50),
    match_value TEXT,
    threshold INT,
    time_window_minutes INT,
    severity ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') DEFAULT 'MEDIUM',
    enabled BOOLEAN DEFAULT 1
);
```

**Fields:**
- `id`: Rule ID
- `rule_name`: Name of detection rule
- `log_field`: Field to match against
- `match_type`: Match method (contains, equals, regex)
- `match_value`: Value to match
- `threshold`: Alert threshold
- `time_window_minutes`: Time window for analysis
- `severity`: Alert severity if triggered
- `enabled`: Whether rule is active

**Typical Row Count:** 2-10 (pre-configured)

---

### Table: anomaly_alert_state

Tracks anomaly detection state for continuous monitoring.

```sql
CREATE TABLE anomaly_alert_state (
    ip_address VARCHAR(45),
    rule_name VARCHAR(255),
    last_alert_time DATETIME
);
```

**Fields:**
- `ip_address`: IP being monitored
- `rule_name`: Anomaly rule name
- `last_alert_time`: Last alert time for this IP/rule

**Typical Row Count:** 0-100 (depends on anomalies)

---

### Table: ip_baselines

Stores baseline metrics for IP-based anomaly detection.

```sql
CREATE TABLE ip_baselines (
    ip_address VARCHAR(45),
    avg_events_per_min FLOAT,
    last_updated DATETIME
);
```

**Fields:**
- `ip_address`: Source IP address
- `avg_events_per_min`: Baseline event rate
- `last_updated`: Last update timestamp

**Typical Row Count:** 1-50 (one per monitored IP)

---

## 4. Database Maintenance

### View Database Size

```sql
SELECT 
    table_name,
    ROUND(((data_length + index_length) / 1024 / 1024), 2) AS size_mb
FROM information_schema.tables
WHERE table_schema = 'mini_siem'
ORDER BY size_mb DESC;
```

### Optimize Tables

```sql
OPTIMIZE TABLE users;
OPTIMIZE TABLE alerts;
OPTIMIZE TABLE logs;
OPTIMIZE TABLE rules;
OPTIMIZE TABLE detection_rules;
```

### Clean Old Data

Clean logs older than 30 days:
```sql
DELETE FROM logs WHERE DATE(log_time) < DATE_SUB(NOW(), INTERVAL 30 DAY);
```

Clean alerts older than 60 days:
```sql
DELETE FROM alerts WHERE DATE(created_time) < DATE_SUB(NOW(), INTERVAL 60 DAY);
```

**Recommended:** Use System Settings UI instead for safe deletion with confirmations.

---

## 5. Backup & Restore

### Backup Database

```bash
mysqldump -u root -p mini_siem > backup_mini_siem.sql
```

Backup with timestamp:
```bash
mysqldump -u root -p mini_siem > backup_mini_siem_$(date +%Y%m%d_%H%M%S).sql
```

### Restore Database

```bash
mysql -u root -p mini_siem < backup_mini_siem.sql
```

### Backup Specific Table

```bash
mysqldump -u root -p mini_siem users > backup_users.sql
```

---

## 6. User Management

### Create New User

```sql
INSERT INTO users (username, password_hash, role, is_active, created_at)
VALUES (
    'username',
    'hashed_password',  -- Use werkzeug to generate
    'analyst',
    1,
    NOW()
);
```

**Note:** Use Flask admin panel instead for security. Password hashing is handled automatically.

### Update User Password

```sql
UPDATE users 
SET password_hash = 'new_hash'
WHERE username = 'target_user';
```

### Disable User Account

```sql
UPDATE users 
SET is_active = 0 
WHERE username = 'target_user';
```

### Check Last Login

```sql
SELECT username, role, last_login FROM users ORDER BY last_login DESC;
```

### Delete User

```sql
DELETE FROM users WHERE username = 'target_user';
```

---

## 7. Alert Management

### View Recent Alerts

```sql
SELECT id, rule_name, severity, status, created_time 
FROM alerts 
ORDER BY created_time DESC 
LIMIT 20;
```

### Count Alerts by Status

```sql
SELECT status, COUNT(*) as count 
FROM alerts 
GROUP BY status;
```

### Count Alerts by Severity

```sql
SELECT severity, COUNT(*) as count 
FROM alerts 
GROUP BY severity 
ORDER BY FIELD(severity, 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW');
```

### Close All Open Alerts

```sql
UPDATE alerts SET status = 'RESOLVED' WHERE status = 'OPEN';
```

---

## 8. Rule Management

### View All Rules

```sql
SELECT id, name, severity, is_active, created_at 
FROM rules;
```

### Enable/Disable Rule

```sql
UPDATE rules SET is_active = 1 WHERE id = 1;  -- Enable
UPDATE rules SET is_active = 0 WHERE id = 1;  -- Disable
```

### Delete Rule

```sql
DELETE FROM rules WHERE id = 1;
```

---

## 9. Common Issues & Solutions

### Issue: Slow Queries

**Symptom:** Alerts and logs pages load slowly

**Solution:**
```sql
-- Check if indexes exist
SHOW INDEX FROM logs;
SHOW INDEX FROM alerts;

-- Optimize tables
OPTIMIZE TABLE logs;
OPTIMIZE TABLE alerts;

-- Check row counts
SELECT COUNT(*) FROM logs;
SELECT COUNT(*) FROM alerts;
```

### Issue: Disk Space Full

**Symptom:** Database errors, no writes possible

**Solution:**
```sql
-- Delete old logs
DELETE FROM logs WHERE DATE(log_time) < DATE_SUB(NOW(), INTERVAL 30 DAY);

-- Delete old alerts
DELETE FROM alerts WHERE DATE(created_time) < DATE_SUB(NOW(), INTERVAL 60 DAY);

-- Optimize
OPTIMIZE TABLE logs;
OPTIMIZE TABLE alerts;
```

### Issue: Connection Refused

**Symptom:** "2003 - Can't connect to MySQL server"

**Solution:**
1. Verify MySQL is running: `mysql -u root -p`
2. Check credentials in `config.py`
3. Verify database name exists: `SHOW DATABASES;`
4. Check firewall isn't blocking port 3306

### Issue: Access Denied

**Symptom:** "1045 - Access denied for user"

**Solution:**
```bash
# Update config.py with correct credentials
# Or reset MySQL password:
mysql -u root -p
ALTER USER 'root'@'localhost' IDENTIFIED BY 'new_password';
FLUSH PRIVILEGES;
```

---

## 10. Performance Tuning

### MySQL Configuration (`my.ini` or `my.cnf`)

```ini
[mysqld]
max_connections = 100
max_allowed_packet = 256M
innodb_buffer_pool_size = 1G
innodb_log_file_size = 256M
query_cache_type = 1
query_cache_size = 256M
```

### Best Practices

- ✅ Use indexes on frequently queried columns
- ✅ Clean old data regularly (use System Settings)
- ✅ Run OPTIMIZE TABLE monthly
- ✅ Backup before major operations
- ✅ Monitor disk space
- ✅ Keep connection pool small (10-20)

---

## 11. Troubleshooting Queries

### Count All Tables

```sql
SELECT 
    table_name,
    table_rows,
    ROUND(((data_length + index_length) / 1024 / 1024), 2) AS size_mb
FROM information_schema.tables
WHERE table_schema = 'mini_siem';
```

### Check User Permissions

```sql
SELECT * FROM mysql.user WHERE user = 'root';
SHOW GRANTS FOR 'root'@'localhost';
```

### View Active Connections

```sql
SHOW PROCESSLIST;
```

### Kill Long-Running Query

```sql
KILL QUERY <process_id>;
```

---

## Support

For issues, refer to:
- `SETUP_GUIDE.md` - General setup and troubleshooting
- `config.py` - Database configuration
- MySQL documentation for advanced topics

**Database is production-ready and fully configured!** 🗄️
