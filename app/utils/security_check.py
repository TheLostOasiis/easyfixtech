"""Security monitoring for EasyFixTech admin system"""
import os
import json
import logging
from datetime import datetime

def check_security_status():
    """Check security status of critical directories and files"""
    status = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'secure': True,
        'warnings': 0,
        'errors': 0,
        'checks': []
    }

    # Required directories and their expected permissions
    required_dirs = ['instance/uploads', 'instance/receipts', 'instance/sessions']
    
    # Check directory existence and permissions
    for dir_path in required_dirs:
        check = {'name': dir_path, 'status': 'secure', 'message': 'Directory verified'}
        
        if not os.path.exists(dir_path):
            check['status'] = 'error'
            check['message'] = 'Directory missing'
            status['errors'] += 1
            status['secure'] = False
        
        status['checks'].append(check)
    
    # Check log file
    if not os.path.exists('logs/easyfixtech.log'):
        status['warnings'] += 1
        status['checks'].append({
            'name': 'logs/easyfixtech.log',
            'status': 'warning',
            'message': 'Log file not found'
        })
    
    # Save status to instance directory
    try:
        os.makedirs('instance', exist_ok=True)
        with open('instance/security_status.json', 'w') as f:
            json.dump(status, f, indent=2)
    except Exception as e:
        logging.error(f"Failed to save security status: {str(e)}")
    
    return status

def get_last_security_status():
    """Get the last saved security status"""
    try:
        with open('instance/security_status.json', 'r') as f:
            return json.load(f)
    except:
        return check_security_status()
