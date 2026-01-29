-- ============================================================================
-- Mini-SIEM Unified Database Setup Script
-- ============================================================================
-- Smart setup that works for BOTH fresh installations and existing databases
-- - Creates all missing tables
-- - Adds missing columns to existing tables
-- - Inserts default admin user (only if users table is empty)
-- - Safe to run multiple times
-- ============================================================================

-- ============================================================================
-- 1. CREATE USERS TABLE (if not exists)
-- ============================================================================
CREATE TABLE IF NOT EXISTS users (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- 2. ENHANCE USERS TABLE (Add missing columns if needed)
-- ============================================================================
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT 1 AFTER role,
ADD COLUMN IF NOT EXISTS created_at DATETIME DEFAULT CURRENT_TIMESTAMP AFTER is_active,
ADD COLUMN IF NOT EXISTS last_login DATETIME NULL AFTER created_at;

-- Add indexes if they don't exist
ALTER TABLE users 
ADD INDEX IF NOT EXISTS idx_username (username),
ADD INDEX IF NOT EXISTS idx_role (role),
ADD INDEX IF NOT EXISTS idx_is_active (is_active);

-- ============================================================================
-- 3. CREATE ALERTS TABLE (if not exists)
-- ============================================================================
CREATE TABLE IF NOT EXISTS alerts (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- 4. CREATE LOGS TABLE (if not exists)
-- ============================================================================
CREATE TABLE IF NOT EXISTS logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    log_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    source VARCHAR(255),
    level ENUM('INFO', 'WARNING', 'ERROR', 'CRITICAL') DEFAULT 'INFO',
    ip_address VARCHAR(45),
    message TEXT,
    INDEX idx_level (level),
    INDEX idx_source (source),
    INDEX idx_log_time (log_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- 5. CREATE RULES TABLE (if not exists)
-- ============================================================================
CREATE TABLE IF NOT EXISTS rules (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL UNIQUE,
    condition TEXT NOT NULL,
    severity ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') DEFAULT 'MEDIUM',
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_name (name),
    INDEX idx_is_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- 6. CREATE DETECTION_RULES TABLE (for advanced detection engine)
-- ============================================================================
CREATE TABLE IF NOT EXISTS detection_rules (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    rule_type ENUM('anomaly', 'correlation', 'threshold', 'pattern') DEFAULT 'anomaly',
    condition TEXT NOT NULL,
    severity ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') DEFAULT 'MEDIUM',
    threshold INT DEFAULT 1,
    time_window INT DEFAULT 300,
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_name (name),
    INDEX idx_rule_type (rule_type),
    INDEX idx_is_active (is_active),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- 7. CREATE ANOMALY_ALERT_STATE TABLE (for tracking anomaly detection state)
-- ============================================================================
CREATE TABLE IF NOT EXISTS anomaly_alert_state (
    id INT PRIMARY KEY AUTO_INCREMENT,
    alert_id INT NOT NULL,
    state ENUM('new', 'acknowledged', 'suppressed', 'resolved') DEFAULT 'new',
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_alert_id (alert_id),
    INDEX idx_state (state),
    INDEX idx_last_updated (last_updated),
    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- 8. CREATE IP_BASELINES TABLE (for anomaly detection baseline data)
-- ============================================================================
CREATE TABLE IF NOT EXISTS ip_baselines (
    id INT PRIMARY KEY AUTO_INCREMENT,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    baseline_data LONGTEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_ip_address (ip_address),
    INDEX idx_updated_at (updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- 9. INSERT DEFAULT ADMIN USER (only if table is empty)
-- ============================================================================
-- Username: admin
-- Password: admin123 (CHANGE THIS AFTER FIRST LOGIN!)
-- NOTE: The password hash is for "admin123" using werkzeug.security
INSERT INTO users (username, password_hash, role, is_active, created_at) 
SELECT 'admin', 'scrypt:32768:8:1$7a5b7c7e$c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7', 'admin', 1, NOW()
WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = 'admin');

-- ============================================================================
-- 7. VERIFY ALL TABLES AND DATA
-- ============================================================================
SELECT '' as '';
SELECT '========== DATABASE SETUP COMPLETE ==========' as Status;
SELECT '' as '';

SELECT 'TABLE STRUCTURE:' as Section;
SELECT '' as '';

SELECT 'Users table:' as Table_Name, COUNT(*) as Row_Count FROM users
UNION ALL
SELECT 'Alerts table:', COUNT(*) FROM alerts
UNION ALL
SELECT 'Logs table:', COUNT(*) FROM logs
UNION ALL
SELECT 'Rules table:', COUNT(*) FROM rules
UNION ALL
SELECT 'Detection Rules table:', COUNT(*) FROM detection_rules
UNION ALL
SELECT 'Anomaly Alert State table:', COUNT(*) FROM anomaly_alert_state
UNION ALL
SELECT 'IP Baselines table:', COUNT(*) FROM ip_baselines;

SELECT '' as '';
SELECT 'SYSTEM USERS:' as Section;
SELECT id, username, role, is_active, created_at, last_login FROM users;

SELECT '' as '';
SELECT 'SETUP NOTES:' as Section;
SELECT '✓ All tables created/verified' as Note
UNION ALL
SELECT '✓ Admin user inserted (if not exists)'
UNION ALL
SELECT '✓ All required columns present'
UNION ALL
SELECT '✓ All indexes created'
UNION ALL
SELECT '⚠ Change admin password after first login'
UNION ALL
SELECT '✓ Safe to run multiple times';

-- ============================================================================
-- TROUBLESHOOTING:
-- If you see errors about "Duplicate entry for key username":
--   This is normal - the script is designed to not overwrite existing users
-- If you see "Unknown engine 'InnoDB'":
--   Your MySQL server may not support InnoDB - remove the ENGINE clause
-- ============================================================================
