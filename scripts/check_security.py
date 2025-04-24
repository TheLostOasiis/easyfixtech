#!/usr/bin/env python3
"""Security check script for EasyFixTech admin system"""
import os
import json
import logging
from datetime import datetime

def setup_logging():
    """Configure logging"""
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    logging.basicConfig(
        filename="logs/easyfixtech.log",
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s [%(process)d] %(message)s (%(pathname)s:%(lineno)d)"
    )

def check_directory_permissions():
    """Check permissions of secure directories"""
    secure_dirs = {
        "instance/sessions": 700,
        "instance/uploads": 700,
        "instance/receipts": 700
    }
    
    issues_found = False
    
    for dir_path, required_perm in secure_dirs.items():
        if os.path.exists(dir_path):
            actual_perm = int(oct(os.stat(dir_path).st_mode)[-3:])
            if actual_perm != required_perm:
                logging.warning(f"Security issue: {dir_path} has permissions {actual_perm}, should be {required_perm}")
                issues_found = True
            else:
                logging.info(f"Security verified: {dir_path} has correct permissions ({required_perm})")
        else:
            logging.error(f"Security error: Required directory missing: {dir_path}")
            issues_found = True
    
    return not issues_found

def save_status(secure, warnings, errors):
    """Save security status to file"""
    status = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'secure': secure,
        'warnings': warnings,
        'errors': errors
    }
    
    with open('instance/security_status.json', 'w') as f:
        json.dump(status, f)

def main():
    """Main security check function"""
    setup_logging()
    logging.info("Starting security verification...")
    
    warnings = errors = 0
    all_secure = check_directory_permissions()
    
    # Count warnings and errors in recent log entries
    with open('logs/easyfixtech.log', 'r') as f:
        recent_logs = f.readlines()[-100:]  # Last 100 entries
        for line in recent_logs:
            if 'WARNING' in line:
                warnings += 1
            elif 'ERROR' in line:
                errors += 1
    
    save_status(all_secure, warnings, errors)
    
    if all_secure:
        logging.info("All security checks passed")
    else:
        logging.warning("Security issues found - check log for details")
    
    logging.info("Security verification completed at " + datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

if __name__ == "__main__":
    main()
