# Automated Security Log Analyzer for Linux

An automated Python script that parses critical Linux log files (`auth.log`, `access.log`, etc.) to detect suspicious activities, aggregates the findings, and generates a daily security report via a text file and email notifications.  

This tool is designed for **system administrators, cybersecurity enthusiasts, and anyone looking to add a foundational layer of automated monitoring to their Linux systems.**

---

## 🔑 Key Features
- **Failed SSH Login Detection:** Identifies and aggregates multiple failed login attempts from the same IP address.  

- **Sudo Command Monitoring:** Logs all commands executed with sudo for an audit trail.  

- **Web Attack Pattern Matching:** Scans web server access logs (e.g., Apache) for common attack signatures like SQL Injection, XSS, and Directory Traversal.  

- **Automated Reporting:** Generates a clean, readable `.txt` report summarizing all findings.  

- **Email Notifications:** Sends the security report directly to your inbox for immediate review.  

- **Easy Automation:** Designed to be run automatically on a schedule using `cron`.  

---

## ⚙️ Technologies Used
- **Scripting:** Python 3  

- **Platform:** Linux (tested on Ubuntu/Debian-based systems)  

- **Core Libraries:** `re` (regex), `smtplib` (email), `os`, `collections`  

---

## 🚀 Getting Started

Follow these instructions to set up and run the log analyzer.

### ✅ Prerequisites
- A Linux-based operating system  

- Python **3.6 or newer**  

- Root or sudo privileges to read system log files  



### 1. Clone the Repository
```bash
git clone https://github.com/your-username/security-log-analyzer.git
cd security-log-analyzer
```



### 2. Configure Email Notifications (Required)

For security, the script reads email credentials from environment variables.<br>
⚠️ Do not hardcode credentials into the script.

**Example for Gmail:**
```bash
export EMAIL_HOST='smtp.gmail.com'
export EMAIL_PORT='465'
export EMAIL_USER='your-email@gmail.com'
export EMAIL_PASSWORD='your-google-app-password'   # Use an App Password, not your regular password
export EMAIL_RECEIVER='destination-email@example.com'
```
**Security Note:** If you are using Gmail or another provider with 2FA, you must generate an App Password in your account security settings.



### 3. Running the Script

You can run the script manually to test it or generate an instant report.<br>
Since the script reads protected log files, run it with sudo.
```bash
sudo -E python3 log_analyzer.py
```

After running, the script will:

- Print its status to the console

- Create a security_report.txt file in the project directory

- Send an email with the report's content

---

## 📄 Sample Report Output
```text
==================================================
Security Log Analysis Report - 2025-09-21 17:20:00
==================================================

[+] Multiple Failed SSH Logins Detected:
-----------------------------------
  - IP: 123.123.123.123, Attempts: 8 <-- HIGH ALERT
  - IP: 192.168.1.105, Attempts: 3

[+] Sudo Commands Executed:
-------------------------
  - /usr/bin/apt update
  - /usr/bin/htop

[+] Potential Web Attack Patterns Detected in Apache Logs:
-------------------------------------------------------
  - Pattern: 'SQL Injection', Count: 5
  - Pattern: 'Directory Traversal', Count: 2

==================================================
End of Report
==================================================
```

---

## ⏰ Automating with Cron

To make the analyzer truly useful, automate it to run daily using cron.

Since cron runs in a minimal environment, it won’t know your exported variables.<br>
The best solution is a wrapper script.



### 1. Create run_analyzer.sh
```bash
#!/bin/bash

# --- Set Credentials ---
export EMAIL_HOST='smtp.gmail.com'
export EMAIL_PORT='465'
export EMAIL_USER='your-email@gmail.com'
export EMAIL_PASSWORD='your-google-app-password'
export EMAIL_RECEIVER='destination-email@example.com'

# --- Run the Script ---
# IMPORTANT: Use the absolute path to your project directory
cd /home/your_user/security-log-analyzer/ && /usr/bin/python3 log_analyzer.py
```



### 2. Make it Executable
```bash
chmod +x run_analyzer.sh
```



### 3. Set Up the Cron Job

Edit the root crontab:
```bash
sudo crontab -e
```

Add the following line to run the analyzer daily at 7 AM:
```bash
# Run the security log analyzer every day at 7 AM
0 7 * * * /home/your_user/security-log-analyzer/run_analyzer.sh
```

Save and exit. The script will now run automatically.

---

## 🔮Possible Enhancements:

- **Analyze More Logs:** Extend the script to parse other logs, like `/var/log/ufw.log` (firewall).

- **IP Geolocation:** Use an API to look up the geographical location of suspicious IP addresses.

- **Threshold-Based Alerting:** Only generate an alert if the number of failed logins from an IP exceeds a certain threshold.
