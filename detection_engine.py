from db import get_connection
from datetime import datetime, timedelta
import time
import smtplib
from email.message import EmailMessage

# ================= EMAIL CONFIG =================

EMAIL_SENDER = "a18102005r@gmail.com"
EMAIL_PASSWORD = "Gmail App Password Here" 
#  NOT your Gmail login password
#  A special password only for apps (like your Python SIEM mail sender)
#  Can be deleted anytime without affecting your Gmail account

# ================ STEP‑BY‑STEP =========================

#  Step 1 — Turn ON 2‑Step Verification
# Google Account → Security → 2‑Step Verification → Turn ON
#  Step 2 — Create App Password
# Google Account → Security → App Passwords
# App → Mail
# Device → Other → type: MiniSIEM
# Click Generate
# You’ll get a 16‑character password → COPY IT

EMAIL_RECEIVER = "a18102005r@gmail.com"



# ================= EMAIL FUNCTION =================

def send_email_alert(subject, body):
    msg = EmailMessage()
    msg["From"] = EMAIL_SENDER
    msg["To"] = EMAIL_RECEIVER
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.send_message(msg)

# ================= ALERT CREATION =================

def create_alert(cursor, rule, severity, details=None):
    now = datetime.now()

    check_query = """
        SELECT id FROM alerts
        WHERE rule_name = %s AND status = 'OPEN'
        AND created_time >= %s
    """

    recent_time = now - timedelta(minutes=5)
    cursor.execute(check_query, (rule, recent_time))

    if cursor.fetchone():
        return  # prevent duplicate alerts

    insert_query = """
        INSERT INTO alerts (rule_name, severity, log_id, created_time, status)
        VALUES (%s, %s, NULL, %s, %s)
    """

    cursor.execute(insert_query, (rule, severity, now, "OPEN"))
    
    # Print formatted alert to terminal
    print("\n" + "="*70)
    print(f"🚨 SECURITY ALERT: {rule}")
    print("="*70)
    print(f"Severity:  {severity}")
    print(f"Time:      {now.strftime('%Y-%m-%d %H:%M:%S')}")
    
    if details:
        print("\n--- DETAILS ---")
        print(details)
    
    print("="*70 + "\n")
    
    body = (
        f"Rule: {rule}\n"
        f"Severity: {severity}\n"
        f"Time: {now}\n"
    )

    if details:
        body += f"\nDetails:\n{details}\n"

    send_email_alert(
        subject=f"SIEM Alert: {rule}",
        body=body
    )


# ================= LOAD RULES FROM DB =================

def load_rules():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM detection_rules WHERE enabled = TRUE")
    rules = cursor.fetchall()

    cursor.close()
    conn.close()

    return rules

# ================= GENERIC RULE EVALUATOR =================

def evaluate_rule(rule):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    time_limit = datetime.now() - timedelta(minutes=rule["time_window_minutes"])

    if rule["match_type"] == "equals":
        condition = f"{rule['log_field']} = %s"
        value = rule["match_value"]
    else:  # contains
        condition = f"{rule['log_field']} LIKE %s"
        value = f"%{rule['match_value']}%"

    query = f"""
        SELECT ip_address, COUNT(*) as hit_count
        FROM logs
        WHERE {condition} AND log_time >= %s
        GROUP BY ip_address
        HAVING hit_count >= %s
    """

    cursor.execute(query, (value, time_limit, rule["threshold"]))
    results = cursor.fetchall()

    for result in results:
        # Create detailed alert for rule-based detection
        details = f"""Detection Type: Rule-Based Detection
Rule Name: {rule['rule_name']}
Log Field: {rule['log_field']}
Match Type: {rule['match_type']}
Match Value: {rule['match_value']}
Threshold: {rule['threshold']} occurrences
Time Window: {rule['time_window_minutes']} minutes
IP Address: {result['ip_address']}
Hit Count: {result['hit_count']}
Detection Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Severity: {rule['severity']}"""
        
        create_alert(cursor, rule["rule_name"], rule["severity"], details=details)

    conn.commit()
    cursor.close()
    conn.close()

# ================ ML- FEATURE  =================

def calculate_current_rates(window_minutes=5):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    time_limit = datetime.now() - timedelta(minutes=window_minutes)

    query = """
        SELECT ip_address, COUNT(*) / %s AS rate
        FROM logs
        WHERE log_time >= %s
        GROUP BY ip_address
    """

    cursor.execute(query, (window_minutes, time_limit))
    results = cursor.fetchall()

    cursor.close()
    conn.close()
    return results

#================ Update Baselines ================
def update_baselines(rates):
    conn = get_connection()
    cursor = conn.cursor()

    for row in rates:
        ip = row["ip_address"]
        rate = row["rate"]

        cursor.execute(
            "SELECT avg_events_per_min FROM ip_baselines WHERE ip_address=%s",
            (ip,)
        )
        existing = cursor.fetchone()

        if existing:
            # Use exponential moving average (weight current rate more heavily)
            new_avg = (float(existing[0]) * 0.3) + (float(rate) * 0.7)  # 70% weight to current rate
            cursor.execute("""
                UPDATE ip_baselines
                SET avg_events_per_min=%s, last_updated=%s
                WHERE ip_address=%s
            """, (new_avg, datetime.now(), ip))
        else:
            cursor.execute("""
                INSERT INTO ip_baselines (ip_address, avg_events_per_min, last_updated)
                VALUES (%s, %s, %s)
            """, (ip, rate, datetime.now()))

    conn.commit()
    cursor.close()
    conn.close()

#================ Anomaly Detection =================
ANOMALY_MULTIPLIER = 1.5  # Changed from 3 - triggers when rate > 1.5x baseline


def detect_anomalies(rates):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    for row in rates:
        ip = row["ip_address"]
        current_rate = row["rate"]

        cursor.execute(
            "SELECT avg_events_per_min FROM ip_baselines WHERE ip_address=%s",
            (ip,)
        )
        base = cursor.fetchone()

        if not base:
            # Initialize baseline on first detection
            cursor.execute("""
                INSERT INTO ip_baselines (ip_address, avg_events_per_min, last_updated)
                VALUES (%s, %s, %s)
            """, (ip, current_rate, datetime.now()))
            print(f"[BASELINE] Initialized for IP={ip} rate={float(current_rate):.2f}")
            continue

        baseline = base["avg_events_per_min"]

        if baseline > 0 and float(current_rate) > float(baseline) * ANOMALY_MULTIPLIER:
            print("\n" + "#"*70)
            print(f"⚠️  ML ALERT - TRAFFIC SPIKE ANOMALY DETECTED")
            print("#"*70)
            print(f"IP Address:       {ip}")
            print(f"Current Rate:     {float(current_rate):.2f} events/min")
            print(f"Baseline Rate:    {float(baseline):.2f} events/min")
            print(f"Multiplier:       {ANOMALY_MULTIPLIER}x")
            print(f"Threshold:        {float(baseline) * ANOMALY_MULTIPLIER:.2f} events/min")
            print(f"Detection Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("#"*70 + "\n")
            
            # Create detailed alert for anomaly detection
            details = f"""Detection Type: Anomaly Detection (ML)
IP Address: {ip}
Current Rate: {float(current_rate):.2f} events/min
Baseline Rate: {float(baseline):.2f} events/min
Anomaly Multiplier: {ANOMALY_MULTIPLIER}x
Threshold: {float(baseline) * ANOMALY_MULTIPLIER:.2f} events/min
Detection Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Severity: MEDIUM"""
            
            create_alert(cursor, "Traffic Spike Anomaly Detected", "MEDIUM", details=details)
        else:
            print(f"[ML] IP={ip} rate={float(current_rate):.2f} baseline={float(baseline):.2f}")

    conn.commit()
    cursor.close()
    conn.close()


# ================= MAIN LOOP =================

if __name__ == "__main__":
    print("Detection engine running (Rules + Anomaly)...")

    while True:
     # Rule-based detection
        rules = load_rules()

        for rule in rules:
            evaluate_rule(rule)
     # ML-style anomaly detection
        rates = calculate_current_rates()
        detect_anomalies(rates)
        update_baselines(rates)


        time.sleep(30)
