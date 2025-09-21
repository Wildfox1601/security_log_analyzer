import re
import os
import smtplib
from collections import Counter
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# --- Configuration ---

LOG_FILES = {
    'auth': '/var/log/auth.log',
    'syslog': '/var/log/syslog',
    'apache_access': '/var/log/apache2/access.log'
}

REGEX_PATTERNS = {
    'failed_ssh': r'Failed password for .* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
    'successful_ssh': r'Accepted password for .* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
    'sudo_commands': r'sudo:.*?COMMAND=(.*)',
    'sql_injection': r'(union|select|insert|update|delete).*(from|where|into)',
    'xss_attack': r'<script>.*</script>',
    'directory_traversal': r'\.\./'
}

# --- Email Configuration ---
# IMPORTANT: For security, use environment variables to store sensitive information.
# Example of setting environment variables in your shell:
# export EMAIL_HOST='smtp.gmail.com'
# export EMAIL_PORT='465'
# export EMAIL_USER='your_email@gmail.com'
# export EMAIL_PASSWORD='your_app_password'
# export EMAIL_RECEIVER='receiver_email@example.com'
EMAIL_CONFIG = {
    'host': os.environ.get('EMAIL_HOST'),
    'port': int(os.environ.get('EMAIL_PORT', 465)), # Default to 465 for SMTPS
    'user': os.environ.get('EMAIL_USER'),
    'password': os.environ.get('EMAIL_PASSWORD'),
    'receiver': os.environ.get('EMAIL_RECEIVER')
}

# --- Core Functions ---

def parse_log_file(log_file_path):
    """
    Reads a log file and returns its lines.
    Handles potential FileNotFoundError if a log file doesn't exist.
    """
    if not os.path.exists(log_file_path):
        print(f"Warning: Log file not found at {log_file_path}. Skipping.")
        return []
    try:
        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as file:
            return file.readlines()
    except PermissionError:
        print(f"Error: Permission denied for {log_file_path}. Try running with sudo.")
        return []
    except Exception as e:
        print(f"An error occurred while reading {log_file_path}: {e}")
        return []

def analyze_logs(lines, pattern_key):
    """
    Analyzes log lines against a specific regex pattern and returns all matches.
    """
    pattern = REGEX_PATTERNS[pattern_key]
    matches = []
    for line in lines:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            matches.append(match.group(1) if match.groups() else match.group(0))
    return matches

def generate_report(analysis_results):
    """
    Formats the analysis results into a human-readable report string.
    """
    report = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report.append("="*50)
    report.append(f"Security Log Analysis Report - {now}")
    report.append("="*50)

    failed_logins = analysis_results.get('failed_ssh_ips', [])
    if failed_logins:
        login_counts = Counter(failed_logins)
        report.append("\n[+] Multiple Failed SSH Logins Detected:")
        report.append("-" * 35)
        for ip, count in login_counts.items():
            if count > 5:
                report.append(f"  - IP: {ip}, Attempts: {count} <-- HIGH ALERT")
            else:
                report.append(f"  - IP: {ip}, Attempts: {count}")
    else:
        report.append("\n[+] No suspicious failed SSH login patterns found.")

    sudo_commands = analysis_results.get('sudo_commands', [])
    if sudo_commands:
        report.append("\n[+] Sudo Commands Executed:")
        report.append("-" * 25)
        for cmd in set(sudo_commands):
             report.append(f"  - {cmd.strip()}")
    else:
        report.append("\n[+] No sudo commands found in the log.")

    web_attacks = analysis_results.get('web_attacks', [])
    if web_attacks:
        report.append("\n[+] Potential Web Attack Patterns Detected in Apache Logs:")
        report.append("-" * 55)
        attack_counts = Counter(web_attacks)
        for attack_type, count in attack_counts.items():
            report.append(f"  - Pattern: '{attack_type}', Count: {count}")
    else:
        report.append("\n[+] No common web attack patterns found in Apache logs.")

    report.append("\n" + "="*50)
    report.append("End of Report")
    report.append("="*50)
    
    return "\n".join(report)

def send_email_report(report_content):
    """
    Sends the generated report via email using configured SMTP settings.
    """
    cfg = EMAIL_CONFIG
    if not all([cfg['host'], cfg['user'], cfg['password'], cfg['receiver']]):
        print("Warning: Email configuration is incomplete. Skipping email notification.")
        return

    print("Attempting to send email report...")
    subject = f"Security Log Analysis Report - {datetime.now().strftime('%Y-%m-%d')}"
    msg = MIMEMultipart()
    msg['From'] = cfg['user']
    msg['To'] = cfg['receiver']
    msg['Subject'] = subject
    msg.attach(MIMEText(report_content, 'plain'))

    try:
        with smtplib.SMTP_SSL(cfg['host'], cfg['port']) as server:
            server.login(cfg['user'], cfg['password'])
            server.send_message(msg)
            print(f"Email report successfully sent to {cfg['receiver']}.")
    except smtplib.SMTPAuthenticationError:
        print("Error: SMTP authentication failed. Check your EMAIL_USER and EMAIL_PASSWORD.")
    except Exception as e:
        print(f"An error occurred while sending the email: {e}")

# --- Main Execution ---

def main():
    """
    Main function to orchestrate the log analysis and report generation.
    """
    print("Starting security log analysis...")
    analysis_results = {}

    auth_log_lines = parse_log_file(LOG_FILES['auth'])
    if auth_log_lines:
        analysis_results['failed_ssh_ips'] = analyze_logs(auth_log_lines, 'failed_ssh')
        analysis_results['sudo_commands'] = analyze_logs(auth_log_lines, 'sudo_commands')

    apache_log_lines = parse_log_file(LOG_FILES['apache_access'])
    if apache_log_lines:
        web_attacks = []
        sql_injections = analyze_logs(apache_log_lines, 'sql_injection')
        if sql_injections: web_attacks.extend(['SQL Injection'] * len(sql_injections))
        xss_attacks = analyze_logs(apache_log_lines, 'xss_attack')
        if xss_attacks: web_attacks.extend(['XSS'] * len(xss_attacks))
        analysis_results['web_attacks'] = web_attacks

    report_content = generate_report(analysis_results)
    report_filename = 'security_report.txt'
    
    try:
        with open(report_filename, 'w') as report_file:
            report_file.write(report_content)
        print(f"Analysis complete. Report saved to '{report_filename}'.")
    except Exception as e:
        print(f"Error: Could not write report file. {e}")
        print("\n--- REPORT ---")
        print(report_content)
    
    send_email_report(report_content)

if __name__ == '__main__':
    main()

