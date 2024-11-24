import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import re
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter
import json
import os
from collections import defaultdict

patterns = {
    'malware': re.compile(r'malware|virus|trojan|ransomware', re.IGNORECASE),
    'file_tampering': re.compile(r'file tampering|unauthorized file modification|file modified|file altered|file changed|file tampered|unauthorized access', re.IGNORECASE),
    'unauthorized_access': re.compile(r'unauthorized access|login failure|invalid login|access denied', re.IGNORECASE),
    'security_breach': re.compile(r'security breach|data breach|intrusion detected|unauthorized entry', re.IGNORECASE),
    'advanced_malware': re.compile(r'zero-day|advanced persistent threat|rootkit', re.IGNORECASE),
    'phishing': re.compile(r'phishing|spear phishing|fraudulent email', re.IGNORECASE),
    'data_leakage': re.compile(r'data leakage|data exfiltration|information leak', re.IGNORECASE),
    'dos_attack': re.compile(r'DoS|denial of service|DDoS', re.IGNORECASE)
}

remedies = {
    'malware': "Remedy: Run a full system antivirus scan, isolate the affected systems, and update your antivirus software.",
    'file_tampering': "Remedy: Restore the affected files from backup, change file permissions, and monitor file integrity.",
    'unauthorized_access': "Remedy: Reset passwords, implement multi-factor authentication, and review access logs.",
    'security_breach': "Remedy: Disconnect affected systems from the network, conduct a thorough investigation, and notify affected parties.",
    'advanced_malware': "Remedy: Employ advanced threat detection tools, perform a deep system scan, and update security protocols.",
    'phishing': "Remedy: Educate users about phishing, implement email filtering solutions, and report the phishing attempt.",
    'data_leakage': "Remedy: Identify the source of the leak, implement data loss prevention solutions, and review data access policies.",
    'dos_attack': "Remedy: Configure firewalls to filter out malicious traffic, use rate limiting to prevent overloading, and implement robust network security measures."
}

config_file = 'log_analyzer_config.json'

def load_patterns():
    global patterns, remedies
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config = json.load(f)
            patterns.update({k: re.compile(v, re.IGNORECASE) for k, v in config.get('patterns', {}).items()})
            remedies.update(config.get('remedies', {}))

def save_patterns():
    config = {
        'patterns': {k: v.pattern for k, v in patterns.items()},
        'remedies': {k: v for k, v in remedies.items()}
    }
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=4)

def analyze_log_file(log_file):
    suspicious_activity = defaultdict(int)
    total_lines = 0
    with open(log_file, 'r') as f:
        for line in f:
            total_lines += 1
            try:
                for activity, pattern in patterns.items():
                    if pattern.search(line):
                        suspicious_activity[activity] += 1
            except Exception as e:
                pass
    return suspicious_activity, total_lines

def save_report(log_file, suspicious_activity, total_lines):
    report_file = log_file.replace('.log', '_output.txt')
    with open(report_file, 'w') as f:
        f.write(f'Total lines processed: {total_lines}\n\n')
        if suspicious_activity:
            for activity, count in suspicious_activity.items():
                percentage = (count / total_lines) * 100
                f.write(f'{activity}: {percentage:.2f}%\n')
                f.write(f'{remedies[activity]}\n\n')
        else:
            f.write('No suspicious activity detected.\n')
    return report_file

def plot_suspicious_activity(log_file, suspicious_activity, total_lines):

    activities = list(suspicious_activity.keys())
    percentages = [(count / total_lines) * 100 for count in suspicious_activity.values()]

    fig, ax = plt.subplots(figsize=(10, 5))

    def get_color(percentage):
        if percentage < 15:
            return 'lightcoral'
        elif 15 <= percentage < 40:
            return 'orangered'
        else:
            return 'darkred'

    colors = [get_color(percentage) for percentage in percentages]

    bars = ax.bar(activities, percentages, color=colors)
    
    ax.set_xlabel('Activity Type')
    ax.set_ylabel('Percentage')
    ax.set_title('Suspicious Activity Detected in Logs (%)')
    ax.yaxis.set_major_formatter(PercentFormatter())

    for bar, percentage in zip(bars, percentages):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), f'{percentage:.2f}%', ha='center', va='bottom')

    legend_labels = [
        "Warning",
        "Alert",
        "Dangerous"
    ]
    color_patches = [plt.Line2D([0], [0], color=get_color(pct), lw=6) for pct in [10, 25, 50]]
    ax.legend(color_patches, legend_labels, title="Severity Levels")

    graph_file = log_file.replace('.log', '_suspicious_activity.png')
    fig.savefig(graph_file)
    plt.close(fig)
    return graph_file

def run_analysis():
    log_file = filedialog.askopenfilename(title="Select Log File", filetypes=[("Log Files", "*.log")])
    if not log_file:
        return

    suspicious_activity, total_lines = analyze_log_file(log_file)
    report_file = save_report(log_file, suspicious_activity, total_lines)
    graph_file = plot_suspicious_activity(log_file, suspicious_activity, total_lines)

    result_message = f"Analysis complete!\nReport saved to: {report_file}"
    if graph_file:
        result_message += f"\nGraph saved to: {graph_file}"
        display_graph(graph_file)

    if suspicious_activity:
        alert_message = "Suspicious activity detected!"
        messagebox.showwarning("Alert", alert_message)

    messagebox.showinfo("Analysis Complete", result_message)
    update_analysis_results(suspicious_activity, total_lines)

def display_graph(graph_file):
    img = tk.PhotoImage(file=graph_file)
    img_label.config(image=img)
    img_label.image = img

def update_analysis_results(suspicious_activity, total_lines):
    for widget in analysis_results_frame.winfo_children():
        widget.destroy()
    
    tk.Label(analysis_results_frame, text=f"Total lines processed: {total_lines}", font=("Helvetica", 12)).pack(pady=5)
    
    if suspicious_activity:
        for activity, count in suspicious_activity.items():
            percentage = (count / total_lines) * 100
            tk.Label(analysis_results_frame, text=f'{activity}: {percentage:.2f}%', font=("Helvetica", 12)).pack(pady=2)
            tk.Label(analysis_results_frame, text=f'{remedies[activity]}', font=("Helvetica", 10)).pack(pady=2)
    else:
        tk.Label(analysis_results_frame, text='No suspicious activity detected.', font=("Helvetica", 12)).pack(pady=5)

def quit_application():
    root.quit()

def add_custom_pattern():
    pattern_name = simpledialog.askstring("Input", "Enter the name of the custom pattern:")
    pattern_regex = simpledialog.askstring("Input", "Enter the regex for the custom pattern:")
    pattern_remedy = simpledialog.askstring("Input", "Enter the Remedies for particular attack:")

    if pattern_name and pattern_regex:
        try:
            patterns[pattern_name] = re.compile(pattern_regex, re.IGNORECASE)
            remedies[pattern_name] = pattern_remedy
            save_patterns()
            messagebox.showinfo("Success", "Custom pattern added successfully.")
        except re.error:
            messagebox.showerror("Error", "Invalid regex pattern.")

load_patterns()

def create_gui():
    global root, tab_analysis, tab_custom_patterns, analysis_results_frame, img_label

    root = tk.Tk()
    root.title("Log Analyzer")
    root.geometry("800x600")

    tab_control = ttk.Notebook(root)
    tab_analysis = ttk.Frame(tab_control)
    tab_custom_patterns = ttk.Frame(tab_control)
    
    tab_control.add(tab_analysis, text='Log Analysis')
    tab_control.add(tab_custom_patterns, text='Custom Patterns')
    tab_control.pack(expand=1, fill='both')

    tk.Label(tab_analysis, text="Log Analyzer Tool", font=("Helvetica", 16)).pack(pady=5)
    tk.Button(tab_analysis, text="Select Log File and Scan", command=run_analysis, font=("Helvetica", 12)).pack(pady=5)
    tk.Button(tab_analysis, text="Quit", command=quit_application, font=("Helvetica", 12)).pack(pady=5)
    
    analysis_results_frame = ttk.Frame(tab_analysis)
    analysis_results_frame.pack(pady=10, padx=10, fill='both', expand=True)

    img_label = tk.Label(tab_analysis)
    img_label.pack(pady=10)

    tk.Label(tab_custom_patterns, text="Custom Pattern Management", font=("Helvetica", 16)).pack(pady=10)
    tk.Button(tab_custom_patterns, text="Add Custom Pattern", command=add_custom_pattern, font=("Helvetica", 12)).pack(pady=10)

    root.mainloop()
if __name__ == '__main__':
    load_patterns()
    create_gui()
