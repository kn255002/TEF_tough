import subprocess
import hashlib
import logging
import os
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Constants
SSH_CONFIG_FILE = "/etc/ssh/sshd_config"
BACKUP_DIR = "/etc/ssh/backups"

def calculate_file_hash(file_path):
    """Calculate the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def backup_file(file_path, backup_dir):
    """Backup a file with a unique hash appended to the filename."""
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    
    file_hash = calculate_file_hash(file_path)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file_name = f"{os.path.basename(file_path)}_{timestamp}_{file_hash}.bak"
    backup_file_path = os.path.join(backup_dir, backup_file_name)
    
    subprocess.run(["cp", file_path, backup_file_path], check=True)
    logger.info(f"Backup created: {backup_file_path}")
    return backup_file_path

def is_ssh_service_installed():
    """Check if the SSH service is installed."""
    try:
        subprocess.run(["systemctl", "status", "ssh"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False

def restart_ssh_service():
    """Restart the SSH service."""
    try:
        subprocess.run(["systemctl", "restart", "ssh"], check=True)
        logger.info("SSH service restarted successfully.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to restart SSH service: {e}")
        raise

def disable_root_login():
    """Disable root login in SSH configuration."""
    try:
        with open(SSH_CONFIG_FILE, "r") as f:
            lines = f.readlines()
        
        # Check if root login is already disabled
        for line in lines:
            if line.strip().startswith("PermitRootLogin") and line.strip() == "PermitRootLogin no":
                logger.info("Root login is already disabled.")
                return
        
        # Modify the file
        with open(SSH_CONFIG_FILE, "w") as f:
            for line in lines:
                if line.strip().startswith("PermitRootLogin"):
                    f.write("PermitRootLogin no\n")
                else:
                    f.write(line)
        
        logger.info("Root login disabled.")
    except Exception as e:
        logger.error(f"Error disabling root login: {e}")
        raise

def change_ssh_port(new_port):
    """Change the SSH port in the configuration file."""
    if not 1 <= new_port <= 65535:
        raise ValueError("Invalid port number. Port must be between 1 and 65535.")
    
    try:
        with open(SSH_CONFIG_FILE, "r") as f:
            lines = f.readlines()
        
        # Check if the port is already set
        for line in lines:
            if line.strip().startswith("Port") and line.strip() == f"Port {new_port}":
                logger.info(f"SSH port is already set to {new_port}.")
                return
        
        # Modify the file
        with open(SSH_CONFIG_FILE, "w") as f:
            for line in lines:
                if line.strip().startswith("Port"):
                    f.write(f"Port {new_port}\n")
                else:
                    f.write(line)
        
        logger.info(f"SSH port changed to {new_port}.")
    except Exception as e:
        logger.error(f"Error changing SSH port: {e}")
        raise

def main():
    try:
        # Check if SSH service is installed
        if not is_ssh_service_installed():
            logger.error("SSH service is not installed or not running.")
            return
        
        # Backup the SSH configuration file
        backup_file(SSH_CONFIG_FILE, BACKUP_DIR)
        
        # Disable root login
        disable_root_login()
        
        # Change SSH port
        change_ssh_port(2222)
        
        # Restart SSH service
        restart_ssh_service()
        
        logger.info("SSH hardening completed successfully.")
    except Exception as e:
        logger.error(f"SSH hardening failed: {e}")

if __name__ == "__main__":
    main()
