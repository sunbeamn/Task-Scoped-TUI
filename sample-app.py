import os

print("[+] Running sample application...")

# 1. Routine access to configuration
if os.path.exists("conftest.py"):
    print("[+] Accessed conftest.py configuration")

# 2. Simulated attempt to access sensitive environment file
if os.path.exists(".env"):
    print("[!] Warning: Reading environment secrets!")

print("[+] Sample application execution completed.")