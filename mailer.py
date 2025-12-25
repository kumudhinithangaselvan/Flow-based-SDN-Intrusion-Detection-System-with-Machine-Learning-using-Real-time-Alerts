import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

# ---------------- HARD-CODED ALERT EMAIL ----------------
ADMIN_EMAIL = "harinijuji@gmail.com"   
SENDER_EMAIL = "testharini10@gmail.com"  
SENDER_PASSWORD = "aode cupx ywzu kjoc"  

# --------------------------------------------------------

def send_attack_alert(employee_id, attack_type, confidence, source):
    """
    Sends email alert when intrusion is detected
    """

    subject = f"🚨 SDN Intrusion Alert - {attack_type}"

    body = f"""
    ALERT: Network Intrusion Detected

    Employee ID : {employee_id}
    Attack Type : {attack_type}
    Confidence  : {confidence:.2f} %
    Source      : {source}
    Time        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

    Immediate investigation is recommended.
    """

    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = ADMIN_EMAIL
    msg["Subject"] = subject

    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, ADMIN_EMAIL, msg.as_string())
        server.quit()
        print("✅ Attack alert email sent")
    except Exception as e:
        print("❌ Email alert failed:", e)
