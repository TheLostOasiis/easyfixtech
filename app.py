from flask import Flask, render_template, request, redirect, send_file, session, url_for, flash
import stripe
import os
import smtplib
import json
import logging
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv
from datetime import datetime, timedelta
import uuid
from functools import wraps


# Load environment variables
load_dotenv()

app = Flask(__name__, template_folder="app/templates", static_folder="app/static")
app.secret_key = os.getenv("SECRET_KEY", "dev-key-change-in-production")

# Stripe keys from .env
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
YOUR_DOMAIN = os.getenv("DOMAIN", 'https://johnseasytech.com')

# Email credentials
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# Admin credentials
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "change-this-password-immediately")

# Load PreBuilt PCs from JSON file with fallback image
DEFAULT_IMAGE = 'static/images/default.jpg'
ORDERS_FILE = 'orders.json'

def load_prebuilts():
    with open('prebuilts.json', 'r') as f:
        prebuilts = json.load(f)
    for pc in prebuilts:
        if 'image' not in pc or not pc['image']:
            pc['image'] = DEFAULT_IMAGE
    return prebuilts


def save_order(order_data):
    try:
        if os.path.exists(ORDERS_FILE):
            with open(ORDERS_FILE, 'r') as f:
                orders = json.load(f)
        else:
            orders = []
        orders.append(order_data)
        with open(ORDERS_FILE, 'w') as f:
            json.dump(orders, f, indent=4)
    except Exception as e:
        print(f"Failed to save order: {e}")


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function



@app.route('/')
def index():
    return render_template('home.html')


@app.route('/prebuilts')
def prebuilts():
    pcs = load_prebuilts()
    return render_template('prebuilts.html', prebuilts=pcs)


@app.route('/custom')
def custom():
    return render_template('custom.html')


@app.route('/support', methods=['GET', 'POST'])
def support_ticket():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        issue = request.form.get('issue')

        subject = f"New Support Ticket from {name}"
        body = f"Name: {name}\nEmail: {email}\nIssue: {issue}"
        message = f"Subject: {subject}\n\n{body}"

        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
                smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
                smtp.sendmail(from_addr=EMAIL_ADDRESS, to_addrs=EMAIL_ADDRESS, msg=message)
        except Exception as e:
            return f"Email failed: {str(e)}"

        return "Support ticket received! We'll get back to you soon."

    return render_template('support.html')


@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    try:
        item_name = request.form['item']
        amount = float(request.form['amount'])
        customer_email = request.form.get('email')
        order_id = str(uuid.uuid4())[:8]

        order_data = {
            "item": item_name,
            "amount": amount,
            "order_id": order_id,
            "email": customer_email,
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        with open('last_receipt.json', 'w') as f:
            json.dump(order_data, f)

        save_order(order_data)

        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': item_name,
                    },
                    'unit_amount': int(amount * 100),
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=YOUR_DOMAIN + '/thankyou',
            cancel_url=YOUR_DOMAIN + '/',
        )
        return redirect(session.url, code=303)
    except Exception as e:
        return str(e)


@app.route('/thankyou')
def thank_you():
    with open('last_receipt.json') as f:
        data = json.load(f)

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.set_text_color(0, 102, 204)
    pdf.cell(200, 10, txt="John's Easy Tech - Purchase Receipt", ln=True, align='C')
    pdf.set_text_color(0, 0, 0)
    pdf.ln(10)
    pdf.cell(200, 10, txt=f"Order #: {data['order_id']}", ln=True)
    pdf.cell(200, 10, txt=f"Item: {data['item']}", ln=True)
    pdf.cell(200, 10, txt=f"Amount Paid: ${data['amount']:.2f}", ln=True)
    pdf.cell(200, 10, txt=f"Date: {data['timestamp']}", ln=True)
    pdf.output("static/receipt.pdf")

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            subject = f"Your Order Receipt - #{data['order_id']}"
            body = f"Thank you for your order with John's Easy Tech!\n\nOrder #: {data['order_id']}\nItem: {data['item']}\nAmount: ${data['amount']:.2f}\nDate: {data['timestamp']}\n\nPlease find your attached PDF receipt."
            message = f"Subject: {subject}\n\n{body}"

            with open("static/receipt.pdf", "rb") as file:
                smtp.sendmail(EMAIL_ADDRESS, data['email'], message)
    except Exception as e:
        print(f"Email failed: {str(e)}")

    return render_template('thankyou.html')


@app.route('/download-receipt')
def download_receipt():
    return send_file("static/receipt.pdf", as_attachment=True)


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)

# Admin authentication decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        flash('Invalid credentials')
    return render_template('admin/login.html')

@app.route('/admin/logout')
@login_required
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
@app.route('/admin/products', methods=['GET', 'POST'])
@admin_required
def admin_products():
    if request.method == 'POST':
        new_product = {
            "name": request.form.get('name'),
            "price": float(request.form.get('price')),
            "description": request.form.get('description'),
            "image": request.form.get('image', DEFAULT_IMAGE)
        }
        
        try:
            prebuilts = load_prebuilts()
            prebuilts.append(new_product)
            
            with open('prebuilts.json', 'w') as f:
                json.dump(prebuilts, f, indent=4)
                
            return redirect(url_for('admin_products'))
        except Exception as e:
            return f"Error adding product: {str(e)}", 500
        
    prebuilts = load_prebuilts()
    return render_template('admin/products.html', products=prebuilts)


def send_test_email():
    """Send a test email to verify email configuration"""
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            subject = "Test Email from John's Easy Tech Admin System"
            body = "This is a test email to verify the email system is working correctly."
            message = f"Subject: {subject}\n\n{body}"
            smtp.sendmail(
                from_addr=EMAIL_ADDRESS,
                to_addrs=EMAIL_ADDRESS,
                msg=message
            )
            app.logger.info("Test email sent successfully")
            return True
    except Exception as e:
        app.logger.error(f"Failed to send test email: {str(e)}")
        return False

# Add test email route (remove in production)
@app.route('/admin/test-email')
@admin_required
def test_email():
    if send_test_email():
        flash('Test email sent successfully!', 'success')
    else:
        flash('Failed to send test email. Check logs for details.', 'danger')
    return redirect(url_for('admin_dashboard'))
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    try:
        # Get products count and recent products
        prebuilts = load_prebuilts()
        products_count = len(prebuilts)
        recent_products = sorted(prebuilts, 
                               key=lambda x: x.get('timestamp', ''), 
                               reverse=True)[:5] if prebuilts else []
        
        # Get orders count if orders file exists
        orders_count = 0
        if os.path.exists(ORDERS_FILE):
            with open(ORDERS_FILE, 'r') as f:
                orders = json.load(f)
                orders_count = len(orders)
        
        # Get email system status
        email_status = True
        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=5) as smtp:
                smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        except Exception as e:
            app.logger.error(f"Email system check failed: {str(e)}")
            email_status = False
        
        return render_template('admin/dashboard.html',
                             products_count=products_count,
                             orders_count=orders_count,
                             recent_products=recent_products,
                             EMAIL_ADDRESS=EMAIL_ADDRESS,
                             email_status=email_status)
    except Exception as e:
        app.logger.error(f"Dashboard error: {str(e)}")
        flash('Error loading dashboard data', 'danger')
        return render_template('error.html', 
                             message="Unable to load dashboard data"), 500

@app.route('/admin/test-email')
@admin_required
def test_email():
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            subject = "Test Email - John's Easy Tech Admin System"
            body = f"""
            This is a test email from your admin system.
            Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            System: John's Easy Tech Admin
            """
            message = f"Subject: {subject}\n\n{body}"
            
            smtp.sendmail(
                from_addr=EMAIL_ADDRESS,
                to_addrs=EMAIL_ADDRESS,
                msg=message
            )
            
        flash('Test email sent successfully!', 'success')
        app.logger.info("Test email sent successfully")
    except Exception as e:
        flash(f'Failed to send test email: {str(e)}', 'danger')
        app.logger.error(f"Test email failed: {str(e)}")
    
    return redirect(url_for('admin_dashboard'))

# Logging setup
def setup_logging(app):
    """Set up logging for the application"""
    if not os.path.exists('logs'):
        os.makedirs('logs', exist_ok=True)
    
    # Create the main application log handler
    file_handler = RotatingFileHandler(
        'logs/easyfixtech.log',
        maxBytes=10240,  # 10KB per file
        backupCount=10   # Keep 10 backup files
    )
    
    # Set log format
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    )
    file_handler.setFormatter(formatter)
    
    # Set logging level
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    
    # Log application startup
    app.logger.info('EasyFixTech startup')
    app.logger.info(f'Email configured for: {EMAIL_ADDRESS}')
    app.logger.info(f'Domain configured as: {YOUR_DOMAIN}')
    
    # Verify directory structure
    for directory in ['instance/uploads', 'instance/receipts']:
        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            app.logger.info(f'Created directory: {directory}')
        else:
            app.logger.info(f'Verified directory: {directory}')

# Initialize logging
setup_logging(app)

# Request logging
@app.before_request
def log_request():
    """Log each request"""
    if not request.path.startswith('/static'):
        app.logger.info(f'Request: {request.method} {request.path} from {request.remote_addr}')

@app.after_request
def log_response(response):
    """Log each response"""
    if not request.path.startswith('/static'):
        app.logger.info(f'Response: {response.status_code} for {request.path}')
    return response

# Error logging
@app.errorhandler(404)
def not_found_error(error):
    app.logger.warning(f'Page not found: {request.path}')
    return render_template('error.html', 
                         message="The requested page was not found",
                         status_code=404), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f'Server Error: {str(error)}')
    return render_template('error.html',
                         message="An internal server error occurred",
                         status_code=500), 500

@app.errorhandler(401)
def unauthorized_error(error):
    app.logger.warning(f'Unauthorized access attempt to {request.path}')
    return render_template('error.html',
                         message="Unauthorized access",
                         status_code=401), 401

# Exception logging
@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(f'Unhandled exception: {str(e)}')
    return render_template('error.html',
                         message="An unexpected error occurred",
                         status_code=500), 500


@app.route('/admin/security-check', methods=['POST'])
@admin_required
def run_security_check():
    """Run security check and return status"""
    try:
        status = check_security_status()
        return jsonify(status), 200
    except Exception as e:
        app.logger.error(f"Security check failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/security-status')
@admin_required
def get_security_status():
    """Get current security status"""
    try:
        status = get_last_security_status()
        return jsonify(status), 200
    except Exception as e:
        app.logger.error(f"Failed to get security status: {str(e)}")
        return jsonify({'error': str(e)}), 500
