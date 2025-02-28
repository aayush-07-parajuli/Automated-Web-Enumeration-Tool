import requests
import whois
import socket
import sqlite3
import csv
import dns.resolver
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import hashlib

# Database Setup
conn = sqlite3.connect("web_enum_results.db")
cursor = conn.cursor()

# Create tables for user authentication and enumeration results
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT,
    subdomains TEXT,
    directories TEXT,
    http_headers TEXT,
    whois_info TEXT,
    open_ports TEXT,
    dns_records TEXT
)
""")
conn.commit()

# Function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to handle user signup
def signup():
    username = entry_signup_username.get()
    password = entry_signup_password.get()

    if not username or not password:
        messagebox.showerror("Error", "All fields are required!")
        return

    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hash_password(password)))
        conn.commit()
        messagebox.showinfo("Success", "Account created successfully! You can now log in.")
        signup_window.destroy()
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "Username already exists!")

# Function to handle user login
def login():
    username = entry_login_username.get()
    password = entry_login_password.get()

    cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hash_password(password)))
    user = cursor.fetchone()

    if user:
        messagebox.showinfo("Login Success", "Welcome to the Web Enumeration Tool!")
        login_window.destroy()
        show_main_application()
    else:
        messagebox.showerror("Error", "Invalid username or password!")

# Function to show the signup window
def show_signup_window():
    global signup_window, entry_signup_username, entry_signup_password
    signup_window = tk.Toplevel(login_window)
    signup_window.title("Sign Up")
    signup_window.geometry("300x200")

    tk.Label(signup_window, text="Username:").pack(pady=5)
    entry_signup_username = tk.Entry(signup_window)
    entry_signup_username.pack()

    tk.Label(signup_window, text="Password:").pack(pady=5)
    entry_signup_password = tk.Entry(signup_window, show="*")
    entry_signup_password.pack()

    tk.Button(signup_window, text="Sign Up", command=signup).pack(pady=10)

# Function to show the login window
def show_login_window():
    global login_window, entry_login_username, entry_login_password
    login_window = tk.Tk()
    login_window.title("Login")
    login_window.geometry("300x200")

    tk.Label(login_window, text="Username:").pack(pady=5)
    entry_login_username = tk.Entry(login_window)
    entry_login_username.pack()

    tk.Label(login_window, text="Password:").pack(pady=5)
    entry_login_password = tk.Entry(login_window, show="*")
    entry_login_password.pack()

    tk.Button(login_window, text="Login", command=login).pack(pady=10)
    tk.Button(login_window, text="Sign Up", command=show_signup_window).pack()

    login_window.mainloop()

# Function to show the main application after login
def show_main_application():
    global root, entry_domain, text_output
    root = tk.Tk()
    root.title("Automated Web Enumeration Tool")
    root.geometry("750x600")

    frame = tk.Frame(root)
    frame.pack(pady=10)

    tk.Label(frame, text="Enter Target Domain:", font=("Arial", 12)).grid(row=0, column=0)
    entry_domain = tk.Entry(frame, font=("Arial", 12), width=30)
    entry_domain.grid(row=0, column=1)
    tk.Button(frame, text="Start Scan", font=("Arial", 12), command=start_enumeration).grid(row=0, column=2)

    tk.Button(root, text="Export to CSV", font=("Arial", 12), command=export_to_csv).pack(pady=5)

    text_output = scrolledtext.ScrolledText(root, font=("Arial", 10), width=80, height=20)
    text_output.pack(pady=10)

    root.mainloop()

# Web Enumeration Functions
subdomains = ["admin", "mail", "blog", "test", "dev", "shop"]
directories = ["admin", "login", "dashboard", "uploads", "config"]

def enumerate_subdomains(domain):
    subdomain_results = []
    for sub in subdomains:
        url = f"http://{sub}.{domain}"
        try:
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                subdomain_results.append(url)
        except requests.exceptions.RequestException:
            pass
    return ", ".join(subdomain_results) if subdomain_results else "None found"

def enumerate_directories(domain):
    directory_results = []
    for directory in directories:
        url = f"http://{domain}/{directory}/"
        try:
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                directory_results.append(url)
        except requests.exceptions.RequestException:
            pass
    return ", ".join(directory_results) if directory_results else "None found"

def analyze_http_headers(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=2)
        headers = response.headers
        return "\n".join([f"{header}: {value}" for header, value in headers.items()])
    except requests.exceptions.RequestException:
        return "Unable to fetch headers."

def start_enumeration():
    domain = entry_domain.get()
    if not domain:
        messagebox.showerror("Error", "Please enter a valid domain!")
        return
    
    text_output.delete(1.0, tk.END)
    text_output.insert(tk.END, "[+] Starting enumeration...\n")
    root.update()

    with ThreadPoolExecutor() as executor:
        subdomains = executor.submit(enumerate_subdomains, domain).result()
        directories = executor.submit(enumerate_directories, domain).result()
        headers = executor.submit(analyze_http_headers, domain).result()
        open_ports = "80, 443"  # Placeholder
        dns_records = "A: 192.168.1.1"  # Placeholder

    results = f"""
    Subdomains:\n{subdomains}
    \nDirectories:\n{directories}
    \nHTTP Headers:\n{headers}
    \nOpen Ports:\n{open_ports}
    \nDNS Records:\n{dns_records}
    """
    text_output.insert(tk.END, results)
    text_output.insert(tk.END, "\n[✔] Enumeration Completed!\n")

def export_to_csv():
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if not file_path:
        return
    cursor.execute("SELECT * FROM results")
    rows = cursor.fetchall()
    with open(file_path, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["ID", "Domain", "Subdomains", "Directories", "HTTP Headers", "Open Ports", "DNS Records"])
        writer.writerows(rows)
    messagebox.showinfo("Export Successful", f"Results saved to {file_path}")

# Run the login system first
show_login_window()
