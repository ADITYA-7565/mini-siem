import requests
from datetime import datetime
import time

url = "http://127.0.0.1:5000/api/logs"

# Send 150 logs to create a spike (3x the baseline)
for i in range(150):
    log = {
        "source": "web-server",
        "level": "INFO",
        "message": "GET /admin/dashboard",
        "ip": "10.0.0.25",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    r = requests.post(url, json=log)
    print("Sent admin access", i+1, r.status_code)
    time.sleep(0.05)  # Send faster to create spike within 5-minute window
