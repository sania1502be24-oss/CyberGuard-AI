from datetime import datetime

def log_alert(message):
    with open("alerts.log", "a") as file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file.write(f"[{timestamp}] {message}\n")