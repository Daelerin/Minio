#!/usr/bin/env python3
import os
import sys
import subprocess
import getpass
import shutil
import re
import requests

def check_dep(cmd):
    if shutil.which(cmd) is None:
        print(f"{cmd} is required but not found.")
        sys.exit(1)

# Dependency check
for cmd in ['wget', 'dpkg', 'getent', 'id', 'chmod', 'chown', 'mv', 'mkdir', 'ip', 'awk', 'cut', 'head', 'journalctl']:
    check_dep(cmd)

# Root privileges check (Linux/Unix only)
if hasattr(os, "geteuid") and os.geteuid() != 0:
    print("This script must be run as root.", file=sys.stderr)
    sys.exit(1)

# Function to get the latest MinIO .deb URL
def get_latest_minio_deb():
    archive_url = "https://dl.min.io/server/minio/release/linux-amd64/archive/"
    try:
        response = requests.get(archive_url)
        response.raise_for_status()
        deb_files = re.findall(r'href="(minio_\d+\.0\.0_amd64\.deb)"', response.text)
        if not deb_files:
            print("No .deb file found on the MinIO website.")
            sys.exit(1)
        latest_deb = sorted(
            deb_files,
            key=lambda x: int(re.search(r'minio_(\d+)\.0\.0_amd64\.deb', x).group(1)),
            reverse=True
        )[0]
        return f"{archive_url}{latest_deb}", latest_deb
    except requests.RequestException as e:
        print(f"Failed to retrieve versions: {e}")
        sys.exit(1)

# Volume path input
repo = input("Enter the volume path: ").strip()

# Create directory if needed
if not os.path.isdir(repo):
    print(f"The directory {repo} does not exist, creating it...")
    try:
        os.makedirs(repo)
    except Exception as e:
        print(f"Error while creating the directory: {e}")
        sys.exit(1)

# Create group and user if needed
if subprocess.call(['getent', 'group', 'minio-user'], stdout=subprocess.DEVNULL) != 0:
    subprocess.run(['groupadd', '-r', 'minio-user'], check=True)
if subprocess.call(['id', 'minio-user'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
    subprocess.run(['useradd', '-r', '-g', 'minio-user', '-s', '/sbin/nologin', 'minio-user'], check=True)
subprocess.run(['chown', 'minio-user:minio-user', repo], check=True)

# Download and install the latest MinIO package
MINIO_DEB = "/tmp/minio.deb"
minio_url, minio_filename = get_latest_minio_deb()
print(f"Downloading the latest version: {minio_url}")
if subprocess.call(['wget', '-qO', MINIO_DEB, minio_url]) != 0:
    print("Failed to download MinIO.")
    sys.exit(1)
if subprocess.call(['dpkg', '-i', MINIO_DEB]) != 0:
    print("Failed to install MinIO.")
    sys.exit(1)

# Modify environment variables in pure Python
var_default = "/etc/default/minio"
if not os.path.isfile(var_default):
    print(f"The file {var_default} does not exist!")
    sys.exit(1)

# Secure the environment file
subprocess.run(['chmod', '640', var_default], check=True)
subprocess.run(['chown', 'root:minio-user', var_default], check=True)

user = input("Enter the admin username for the console: ").strip()

# Masked password input
while True:
    password = getpass.getpass("Enter the admin password: ")
    password2 = getpass.getpass("Confirm the password: ")
    if password == password2:
        break
    print("Passwords do not match. Please try again.")

def update_env_file(filename, updates):
    # Read all lines
    with open(filename, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    # Modify lines according to updates (dict)
    new_lines = []
    for line in lines:
        matched = False
        for key, value in updates.items():
            if line.strip().startswith(f"{key}="):
                new_lines.append(f'{key}="{value}"\n')
                matched = True
                break
        if not matched:
            new_lines.append(line)
    # Add missing keys
    for key, value in updates.items():
        if not any(l.strip().startswith(f"{key}=") for l in lines):
            new_lines.append(f'{key}="{value}"\n')
    # Write the file
    with open(filename, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)

update_env_file(var_default, {
    "MINIO_ROOT_USER": user,
    "MINIO_ROOT_PASSWORD": password,
    "MINIO_VOLUMES": repo
})

# Create self-signed certificate
CERTGEN = "/tmp/certgen-linux-amd64"
certgen_url = "https://github.com/minio/certgen/releases/latest/download/certgen-linux-amd64"
if subprocess.call(['wget', '-qO', CERTGEN, certgen_url]) != 0:
    print("Failed to download certgen.")
    sys.exit(1)
subprocess.run(['chmod', '+x', CERTGEN], check=True)

# Automatic detection or manual input of IP address
def is_valid_ipv4(ip):
    if not re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}$", ip):
        return False
    parts = [int(x) for x in ip.split('.')]
    return all(0 <= part <= 255 for part in parts)

multi_ip = input("Do you want to automatically detect the IP address (y/n): ").strip().lower()

if multi_ip == "n":
    # User wants to choose the IP manually
    while True:
        address = input("What is your server's IP address?: ").strip()
        if is_valid_ipv4(address):
            break
        print("Invalid IP address, please try again.")
else:
    # Automatic detection with user validation
    while True:
        try:
            address = subprocess.check_output(
                "ip -o -4 addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1",
                shell=True, text=True
            ).strip()
        except Exception:
            address = ""
        print(f"Automatically detected IP address: {address}")
        valid = input("Do you confirm this IP? (y/n): ").strip().lower()
        if valid == "y":
            break
        else:
            address = input("Please enter the IP address to use: ").strip()
            if is_valid_ipv4(address):
                break
            print("Invalid IP address, please try again.")

print("Generate the certificate")
subprocess.run([CERTGEN, "-host", f"127.0.0.1,localhost,{address}"], check=True)

# Prepare the certs folder
CERT_DIR = "/home/minio-user/.minio/certs"
os.makedirs(CERT_DIR, exist_ok=True)
try:
    shutil.move("public.crt", CERT_DIR)
    shutil.move("private.key", CERT_DIR)
except Exception as e:
    print(f"Error while moving certificates: {e}")
    sys.exit(1)
subprocess.run(['chown', '-R', 'minio-user:minio-user', "/home/minio-user/.minio"], check=True)

print("Clean up temporary files")
for f in [MINIO_DEB, CERTGEN]:
    try:
        os.remove(f)
    except Exception:
        pass

print("Installation complete. Here are the last lines from the MinIO journal:")
subprocess.call(['journalctl', '-xeu', 'minio', '-n', '7'])

print("Access the MinIO console with:")
print(f"  Username: {user}")
print("  Password: (the one you chose)")
print(f"  URL: https://{address}:9000")
print("You can access the MinIO console at https://<your-ip>:9001")
