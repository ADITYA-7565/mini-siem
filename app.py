from flask import Flask, request, jsonify
from db import get_connection
from datetime import datetime, timedelta
from flask import render_template
from flask import redirect, url_for
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash
from models.user_model import get_user_by_username, get_user_by_id
from auth import role_required
import json



app = Flask(__name__)

app.secret_key = "mini_siem_secret_key"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return get_user_by_id(user_id)


# ================= DASHBOARD ROUTE =================

@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    # Get critical alerts (last 24 hours)
    cursor.execute("""
        SELECT COUNT(*) AS count FROM alerts 
        WHERE severity = 'HIGH' AND created_time >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
    """)
    critical_count = cursor.fetchone()["count"]

    # Get open alerts
    cursor.execute("SELECT COUNT(*) AS count FROM alerts WHERE status = 'OPEN'")
    open_alerts = cursor.fetchone()["count"]

    # Get total alerts (24h)
    cursor.execute("""
        SELECT COUNT(*) AS count FROM alerts 
        WHERE created_time >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
    """)
    total_alerts_24h = cursor.fetchone()["count"]

    # Get total rules and active rules
    cursor.execute("SELECT COUNT(*) AS count FROM detection_rules")
    total_rules = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) AS count FROM detection_rules WHERE enabled = TRUE")
    active_rules = cursor.fetchone()["count"]

    # Get events per hour (last hour)
    cursor.execute("""
        SELECT COUNT(*) AS count FROM logs 
        WHERE log_time >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
    """)
    events_per_hour = cursor.fetchone()["count"]

    # Get unique IPs (last 24h)
    cursor.execute("""
        SELECT COUNT(DISTINCT ip_address) AS count FROM logs 
        WHERE log_time >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
    """)
    unique_ips = cursor.fetchone()["count"]

    # Get rules triggered (last 24h)
    cursor.execute("""
        SELECT COUNT(DISTINCT rule_name) AS count FROM alerts 
        WHERE created_time >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
    """)
    rules_triggered = cursor.fetchone()["count"]

    # Calculate threat level
    threat_level = "🟢 LOW"
    if critical_count >= 10:
        threat_level = "🔴 CRITICAL"
    elif critical_count >= 5:
        threat_level = "🔶 HIGH"
    elif critical_count >= 2:
        threat_level = "🟡 MEDIUM"

    # Get recent activities (last 10 alerts)
    cursor.execute("""
        SELECT rule_name AS description, severity AS type, created_time 
        FROM alerts 
        ORDER BY created_time DESC 
        LIMIT 10
    """)
    recent_activities_data = cursor.fetchall()
    
    recent_activities = []
    for activity in recent_activities_data:
        time_diff = datetime.now() - activity["created_time"]
        if time_diff.seconds < 60:
            time_str = f"{time_diff.seconds}s ago"
        elif time_diff.seconds < 3600:
            time_str = f"{time_diff.seconds // 60}m ago"
        else:
            time_str = f"{time_diff.seconds // 3600}h ago"
        
        recent_activities.append({
            "type": activity["type"],
            "description": activity["description"],
            "time": time_str
        })

    cursor.close()
    conn.close()

    return render_template(
        "dashboard.html",
        critical_count=critical_count,
        open_alerts=open_alerts,
        total_alerts_24h=total_alerts_24h,
        total_rules=total_rules,
        active_rules=active_rules,
        events_per_hour=events_per_hour,
        unique_ips=unique_ips,
        rules_triggered=rules_triggered,
        threat_level=threat_level,
        recent_activities=recent_activities
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        user = get_user_by_username(request.form["username"])

        if user and check_password_hash(user.password_hash, request.form["password"]):
            login_user(user)
            # update last_login timestamp for the user
            try:
                conn = get_connection()
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET last_login = NOW() WHERE id = %s", (user.id,))
                conn.commit()
            except Exception as e:
                print(f"Failed to update last_login: {e}")
            finally:
                try:
                    cursor.close()
                except:
                    pass
                try:
                    conn.close()
                except:
                    pass

            return redirect("/alerts")
        else:
            error = "Invalid credentials"

    return render_template("login.html", error=error)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")


@app.route("/admin/rules")
@login_required
@role_required("admin")
def view_rules():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM detection_rules")
    rules = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("rules.html", rules=rules)

@app.route("/admin/rules/disable/<int:rule_id>")
@login_required
@role_required("admin")
def disable_rule(rule_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE detection_rules SET enabled = FALSE WHERE id=%s", (rule_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect("/admin/rules")


@app.route("/admin/rules/enable/<int:rule_id>")
@login_required
@role_required("admin")
def enable_rule(rule_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE detection_rules SET enabled = TRUE WHERE id=%s", (rule_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect("/admin/rules")

@app.route("/admin/rules/add", methods=["GET", "POST"])
@login_required
@role_required("admin")
def add_rule():
    if request.method == "POST":
        data = (
            request.form["rule_name"],
            request.form["log_field"],
            request.form["match_type"],
            request.form["match_value"],
            int(request.form["threshold"]),
            int(request.form["time_window"]),
            request.form["severity"]
        )

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO detection_rules
            (rule_name, log_field, match_type, match_value, threshold, time_window_minutes, severity)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, data)

        conn.commit()
        cursor.close()
        conn.close()

        return redirect("/admin/rules")

    return render_template("add_rule.html")


@app.route("/api/logs", methods=["POST"])
def receive_logs():
    data = request.get_json()

    required_fields = ["source", "level", "message", "ip", "timestamp"]
    if not data or not all(field in data for field in required_fields):
        return jsonify({"error": "Invalid log format"}), 400

    conn = get_connection()
    cursor = conn.cursor()

    query = """
        INSERT INTO logs (source, level, message, ip_address, log_time)
        VALUES (%s, %s, %s, %s, %s)
    """

    values = (
        data["source"],
        data["level"],
        data["message"],
        data["ip"],
        data["timestamp"]
    )

    cursor.execute(query, values)
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"status": "log saved"}), 201


@app.route("/alerts")
@login_required
def view_alerts():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    # Get filter parameters from request
    severity = request.args.get('severity', '')
    status = request.args.get('status', '')
    search = request.args.get('search', '')
    date_from = request.args.get('dateFrom', '')
    date_to = request.args.get('dateTo', '')

    # Build query with filters
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []

    if severity:
        query += " AND severity = %s"
        params.append(severity)

    if status:
        query += " AND status = %s"
        params.append(status)

    if search:
        query += " AND (rule_name LIKE %s OR message LIKE %s)"
        search_param = f"%{search}%"
        params.extend([search_param, search_param])

    if date_from:
        query += " AND DATE(created_time) >= %s"
        params.append(date_from)

    if date_to:
        query += " AND DATE(created_time) <= %s"
        params.append(date_to)

    query += " ORDER BY created_time DESC"

    cursor.execute(query, params)
    alerts = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) AS total FROM alerts")
    total_alerts = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS open_count FROM alerts WHERE status = 'OPEN'")
    open_alerts = cursor.fetchone()["open_count"]

    cursor.close()
    conn.close()

    return render_template(
        "alerts.html",
        alerts=alerts,
        total=total_alerts,
        open_count=open_alerts
    )

@app.route("/close_alert/<int:alert_id>")
def close_alert(alert_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE alerts SET status = 'CLOSED' WHERE id = %s",
        (alert_id,)
    )

    conn.commit()
    cursor.close()
    conn.close()

    # return "<h3>Alert closed.</h3><a href='/alerts'>Back to Alerts</a>"
    return redirect(url_for("view_alerts"))

    # return render_template(
    #     "alerts.html",
    #     alerts=alerts,
    #     total=total_alerts,
    #     open_count=open_alerts
    # )



@app.route("/logs")
@login_required
def view_logs():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    # Get filter parameters from request
    level = request.args.get('level', '')
    source = request.args.get('source', '')
    ip = request.args.get('ip', '')
    search = request.args.get('search', '')
    date_from = request.args.get('dateFrom', '')
    date_to = request.args.get('dateTo', '')

    # Build query with filters
    query = "SELECT * FROM logs WHERE 1=1"
    params = []

    if level:
        query += " AND level = %s"
        params.append(level)

    if source:
        query += " AND source = %s"
        params.append(source)

    if ip:
        query += " AND ip_address = %s"
        params.append(ip)

    if search:
        query += " AND message LIKE %s"
        params.append(f"%{search}%")

    if date_from:
        query += " AND DATE(log_time) >= %s"
        params.append(date_from)

    if date_to:
        query += " AND DATE(log_time) <= %s"
        params.append(date_to)

    query += " ORDER BY log_time DESC LIMIT 10000"

    cursor.execute(query, params)
    logs = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("logs.html", logs=logs)


@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect("/dashboard")
    return redirect("/login")

@app.route("/admin/settings", methods=["GET", "POST"])
@login_required
@role_required("admin")
def system_settings():
    import platform
    import os
    
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    
    if request.method == "GET":
        # Gather system information
        cursor.execute("SELECT VERSION() as version")
        db_version = cursor.fetchone()["version"]
        
        cursor.execute("SELECT COUNT(*) as count FROM logs")
        log_count = cursor.fetchone()["count"]
        
        cursor.execute("SELECT COUNT(*) as count FROM alerts")
        alert_count = cursor.fetchone()["count"]
        
        cursor.execute("SELECT COUNT(*) as count FROM detection_rules")
        rule_count = cursor.fetchone()["count"]
        
        cursor.execute("SELECT COUNT(*) as count FROM users WHERE is_active = 1")
        active_users = cursor.fetchone()["count"]
        
        system_info = {
            'db_version': db_version,
            'os': platform.system(),
            'python_version': platform.python_version(),
            'log_count': log_count,
            'alert_count': alert_count,
            'rule_count': rule_count,
            'active_users': active_users,
            'db_host': 'localhost',
            'db_name': 'mini_siem'
        }
        
        cursor.close()
        conn.close()
        
        return render_template("settings.html", system_info=system_info)
    
    elif request.method == "POST":
        # Handle settings updates (for future expansion)
        action = request.form.get("action", "")
        
        if action == "backup":
            # Log the backup request
            print("Backup requested by:", current_user.username)
            cursor.close()
            conn.close()
            return redirect(url_for("system_settings"))
        
        elif action == "clear_old_logs":
            days = int(request.form.get("days", 30))
            try:
                cursor.execute("DELETE FROM logs WHERE DATE(log_time) < DATE_SUB(NOW(), INTERVAL %s DAY)", (days,))
                conn.commit()
            except Exception as e:
                conn.rollback()
                print(f"Error clearing logs: {e}")
        
        elif action == "clear_old_alerts":
            days = int(request.form.get("days", 60))
            try:
                cursor.execute("DELETE FROM alerts WHERE DATE(created_time) < DATE_SUB(NOW(), INTERVAL %s DAY)", (days,))
                conn.commit()
            except Exception as e:
                conn.rollback()
                print(f"Error clearing alerts: {e}")
        
        cursor.close()
        conn.close()
        
        return redirect(url_for("system_settings"))



@app.route("/admin/users")
@login_required
@role_required("admin")
def manage_users():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT id, username, role, is_active, created_at, last_login FROM users ORDER BY created_at DESC")
    users = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template("users.html", users=users)

@app.route("/admin/users/create", methods=["POST"])
@login_required
@role_required("admin")
def create_user():
    from werkzeug.security import generate_password_hash
    
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    role = request.form.get("role", "analyst")
    
    if not username or not password:
        return redirect(url_for("manage_users"))
    
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        password_hash = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (username, password_hash, role, is_active, created_at) VALUES (%s, %s, %s, %s, NOW())",
            (username, password_hash, role, 1)
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"Error creating user: {e}")
    finally:
        cursor.close()
        conn.close()
    
    return redirect(url_for("manage_users"))

@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
@role_required("admin")
def edit_user(user_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    
    if request.method == "GET":
        # Fetch user details to pre-populate form
        cursor.execute("SELECT id, username, role, is_active FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not user:
            return redirect(url_for("manage_users"))
        
        return render_template("edit_user.html", user=user)
    
    elif request.method == "POST":
        # Handle user update
        from werkzeug.security import generate_password_hash
        
        role = request.form.get("role", "analyst")
        is_active = request.form.get("is_active", "0") == "1"
        password = request.form.get("password", "").strip()
        
        try:
            if password:
                # If password provided, update it
                password_hash = generate_password_hash(password)
                cursor.execute(
                    "UPDATE users SET role = %s, is_active = %s, password_hash = %s WHERE id = %s",
                    (role, 1 if is_active else 0, password_hash, user_id)
                )
            else:
                # Update only role and is_active if no password provided
                cursor.execute(
                    "UPDATE users SET role = %s, is_active = %s WHERE id = %s",
                    (role, 1 if is_active else 0, user_id)
                )
            conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"Error updating user: {e}")
        finally:
            cursor.close()
            conn.close()
        
        return redirect(url_for("manage_users"))


@app.route("/admin/users/<int:user_id>/delete")
@login_required
@role_required("admin")
def delete_user(user_id):
    # Prevent self-deletion
    if user_id == current_user.id:
        return redirect(url_for("manage_users"))
    
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"Error deleting user: {e}")
    finally:
        cursor.close()
        conn.close()
    
    return redirect(url_for("manage_users"))


if __name__ == "__main__":
    app.run(debug=True)
