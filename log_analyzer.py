import re
import os
from collections import Counter
from datetime import datetime

# --- Configuration ---

# Define the paths to the log files you want to analyze.
# Add or remove paths as needed for your system.
LOG_FILES = {
    'auth': '/var/log/auth.log',
    'syslog': '/var/log/syslog',
    'apache_access': '/var/log/apache2/access.log'
}

# Define regular expressions to detect suspicious patterns.
# These patterns identify common indicators of compromise (IoCs).
REGEX_PATTERNS = {
    'failed_ssh': r'Failed password for .* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
    'successful_ssh': r'Accepted password for .* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
    'sudo_commands': r'sudo:.*?COMMAND=(.*)',
    'sql_injection': r'(union|select|insert|update|delete).*(from|where|into)',
    'xss_attack': r'<script>.*</script>',
    'directory_traversal': r'\.\./'
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
            # Return the full match or a specific group if defined in regex
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

    # Failed SSH Login Report
    failed_logins = analysis_results.get('failed_ssh_ips', [])
    if failed_logins:
        login_counts = Counter(failed_logins)
        report.append("\n[+] Multiple Failed SSH Logins Detected:")
        report.append("-" * 35)
        for ip, count in login_counts.items():
            if count > 5:  # Flagging IPs with more than 5 failed attempts
                report.append(f"  - IP: {ip}, Attempts: {count} <-- HIGH ALERT")
            else:
                report.append(f"  - IP: {ip}, Attempts: {count}")
    else:
        report.append("\n[+] No suspicious failed SSH login patterns found.")

    # Sudo Command Report
    sudo_commands = analysis_results.get('sudo_commands', [])
    if sudo_commands:
        report.append("\n[+] Sudo Commands Executed:")
        report.append("-" * 25)
        for cmd in set(sudo_commands): # Use set to show unique commands
             report.append(f"  - {cmd.strip()}")
    else:
        report.append("\n[+] No sudo commands found in the log.")

    # Web Attack Report
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


# --- Main Execution ---

def main():
    """
    Main function to orchestrate the log analysis and report generation.
    """
    print("Starting security log analysis...")
    
    analysis_results = {}

    # 1. Analyze auth.log for SSH and Sudo activity
    auth_log_lines = parse_log_file(LOG_FILES['auth'])
    if auth_log_lines:
        failed_ssh_ips = analyze_logs(auth_log_lines, 'failed_ssh')
        sudo_cmds = analyze_logs(auth_log_lines, 'sudo_commands')
        analysis_results['failed_ssh_ips'] = failed_ssh_ips
        analysis_results['sudo_commands'] = sudo_cmds

    # 2. Analyze Apache access.log for web attacks
    apache_log_lines = parse_log_file(LOG_FILES['apache_access'])
    if apache_log_lines:
        sql_injections = analyze_logs(apache_log_lines, 'sql_injection')
        xss_attacks = analyze_logs(apache_log_lines, 'xss_attack')
        dir_traversals = analyze_logs(apache_log_lines, 'directory_traversal')
        
        # Consolidate web attack findings
        web_attacks = []
        if sql_injections: web_attacks.extend(['SQL Injection'] * len(sql_injections))
        if xss_attacks: web_attacks.extend(['XSS'] * len(xss_attacks))
        if dir_traversals: web_attacks.extend(['Directory Traversal'] * len(dir_traversals))
        analysis_results['web_attacks'] = web_attacks

    # 3. Generate and save the report
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


if __name__ == '__main__':
    # Ensure the script is being run and not imported
    main()

