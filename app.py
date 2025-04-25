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
from flask import jsonify
from fpdf import FPDF



# Load environment variables
load_dotenv()

app = Flask(__name__, template_folder="app/templates", static_folder="app/static")
app.secret_key = os.getenv("SECRET_KEY", "dev-key-change-in-production")

# Stripe keys from .env
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
YOUR_DOMAIN = os.getenv("DOMAIN", 'https://johnseasytech.com')

#Persistant Data Vars
DATA_DIR = "/data"
PREBUILT_FILE = os.path.join(DATA_DIR, "prebuilts.json")
TICKETS_FILE = os.path.join(DATA_DIR, "tickets.json")
ORDERS_FILE = os.path.join(DATA_DIR, "orders.json")


# Email credentials
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# Admin credentials
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "change-this-password-immediately")

# Load PreBuilt PCs from JSON file with fallback image
DEFAULT_IMAGE = 'static/images/default.jpg'
ORDERS_FILE = 'orders.json'

# Admin authentication decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def initialize_data_files():
    # Make sure the /data directory exists
    os.makedirs(DATA_DIR, exist_ok=True)

    # Default Prebuilt PCs to load on first run
    default_prebuilts = [
        {
            "name": "Gamer Beast 5000",
            "price": 1499.99,
            "description": "A top-tier rig with RTX 4070 Super and Ryzen 7 7800X3D.",
            "image": "static/images/default.jpg",
            "category": "Gaming"
        },
        {
            "name": "Code Cruncher Pro",
            "price": 899.99,
            "description": "Perfect for developers, preloaded with Linux and 32GB RAM.",
            "image": "static/images/default.jpg",
            "category": "Programming"
        }
    ]

    if not os.path.exists(PREBUILT_FILE):
        with open(PREBUILT_FILE, 'w') as f:
            json.dump(default_prebuilts, f, indent=4)

    if not os.path.exists(TICKETS_FILE):
        with open(TICKETS_FILE, 'w') as f:
            json.dump([], f)

    if not os.path.exists(ORDERS_FILE):
        with open(ORDERS_FILE, 'w') as f:
            json.dump([], f)


def categorize_prebuilts():
    pcs = load_prebuilts()
    categories = {}
    for pc in pcs:
        cat = pc.get('category', 'Uncategorized')
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(pc)
    return categories


def load_prebuilts():
    if os.path.exists(PREBUILT_FILE):
        with open(PREBUILT_FILE, 'r') as f:
            prebuilts = json.load(f)
    else:
        prebuilts = []

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

@app.route('/terms')
def terms():
    return render_template('terms.html')



@app.route('/prebuilts')
def prebuilts():
    pcs = load_prebuilts()
    categories = ['Gaming', 'Programming', 'Video Editing', 'General Use']
    categorized_pcs = {cat: [] for cat in categories}

    for pc in pcs:
        category = pc.get("category", "General Use")
        categorized_pcs.setdefault(category, []).append(pc)

    return render_template("prebuilts.html", categorized_pcs=categorized_pcs)


@app.route('/custom')
def custom():
    return render_template('custom.html')


@app.route('/support', methods=['GET', 'POST'])
def support_ticket():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        issue = request.form.get('issue')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        ticket = {
            "id": str(uuid.uuid4()),
            "name": name,
            "email": email,
            "issue": issue,
            "timestamp": timestamp,
            "status": "open"
        }

        # Save ticket to JSON
        try:
            if os.path.exists("tickets.json"):
                with open("tickets.json", "r") as f:
                    tickets = json.load(f)
            else:
                tickets = []

            tickets.append(ticket)

            with open("tickets.json", "w") as f:
                json.dump(tickets, f, indent=4)
        except Exception as e:
            print(f"Error saving ticket: {str(e)}")

        # Send email
        try:
            subject = f"New Support Ticket from {name}"
            body = f"Name: {name}\nEmail: {email}\nIssue: {issue}\nTime: {timestamp}"
            message = f"Subject: {subject}\n\n{body}"

            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
                smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
                smtp.sendmail(from_addr=EMAIL_ADDRESS, to_addrs=EMAIL_ADDRESS, msg=message)
        except Exception as e:
            print(f"Email failed: {str(e)}")

        return render_template("support_thankyou.html", name=name)

    return render_template("support.html")



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


@app.route('/admin/add_product', methods=['POST'])
@login_required
def add_product():
    new_product = {
        "name": request.form.get("name"),
        "specs": request.form.get("specs"),
        "price": float(request.form.get("price")),
        "image": request.form.get("image", DEFAULT_IMAGE)
    }
    try:
        prebuilts = load_prebuilts()
        prebuilts.append(new_product)
        with open("prebuilts.json", "w") as f:
            json.dump(prebuilts, f, indent=4)
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        return f"Error adding product: {str(e)}", 500


@app.route('/admin/delete_product/<int:index>', methods=['GET'])
@login_required
def delete_product(index):
    try:
        prebuilts = load_prebuilts()
        if 0 <= index < len(prebuilts):
            prebuilts.pop(index)
            with open("prebuilts.json", "w") as f:
                json.dump(prebuilts, f, indent=4)
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        return f"Error deleting product: {str(e)}", 500


@app.route('/admin/close_ticket/<ticket_id>', methods=['GET'])
@login_required
def close_ticket(ticket_id):
    try:
        if os.path.exists("tickets.json"):
            with open("tickets.json", "r") as f:
                tickets = json.load(f)
            for ticket in tickets:
                if ticket["id"] == ticket_id:
                    ticket["status"] = "closed"
            with open("tickets.json", "w") as f:
                json.dump(tickets, f, indent=4)
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        return f"Error closing ticket: {str(e)}", 500




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
    pdf.ln(10)
    pdf.set_font("Arial", size=10)
    pdf.multi_cell(200, 10,
    txt="By completing this order, you agreed to the Terms and Conditions, Warranty Policy, Legal Disclaimers, and Tech Support Agreement. Read them at johnseasytech.com/terms.")

    pdf.output("static/receipt.pdf")

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            subject = f"Your Order Receipt - #{data['order_id']}"
            body = f"Thank you for your order with John's Easy Tech!\n\nOrder #: {data['order_id']}\nItem: {data['item']}\nAmount: ${data['amount']:.2f}\nDate: {data['timestamp']}\n\nPlease find your attached PDF receipt.\n\nBy submitting this order, you agreed to all terms listed at {YOUR_DOMAIN}/terms."
            message = f"Subject: {subject}\n\n{body}"

            with open("static/receipt.pdf", "rb") as file:
                smtp.sendmail(EMAIL_ADDRESS, data['email'], message)
    except Exception as e:
        print(f"Email failed: {str(e)}")

    return render_template('thankyou.html')


@app.route('/download-receipt')
def download_receipt():
    return send_file("static/receipt.pdf", as_attachment=True)


@app.route('/admin/dashboard', methods=['GET'])
@login_required
def admin_dashboard():
    try:
        # Load Prebuilt products
        products = load_prebuilts()

        # Load Tickets
        tickets = []
        if os.path.exists("tickets.json"):
            with open("tickets.json", "r") as f:
                tickets = json.load(f)

        # Search filter (GET param)
        query = request.args.get("search", "").strip().lower()
        if query:
            tickets = [t for t in tickets if query in t.get("name", "").lower()
                       or query in t.get("email", "").lower()
                       or query in t.get("issue", "").lower()
                       or query in t.get("status", "").lower()]

        return render_template("admin/dashboard.html", products=products, tickets=tickets)

    except Exception as e:
        app.logger.error(f"Dashboard error: {str(e)}")
        return render_template("error.html", message="Dashboard failed"), 500



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

@app.route('/admin/products', methods=['GET', 'POST'])
@admin_required
def admin_products():
    categories = ["Gaming", "Programming", "Video Editing", "General Use"]

    if request.method == 'POST':
        new_product = {
            "name": request.form.get('name'),
            "price": float(request.form.get('price')),
            "description": request.form.get('description'),
            "image": request.form.get('image', DEFAULT_IMAGE),
            "category": request.form.get('category', "General Use")
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
    categorized_pcs = {cat: [] for cat in categories}
    for pc in prebuilts:
        category = pc.get('category', 'General Use')
        categorized_pcs.setdefault(category, []).append(pc)

    return render_template('admin/products.html', categories=categories, categorized_pcs=categorized_pcs)


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

initialize_data_files()


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)


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





for rule in app.url_map.iter_rules():
    print(rule)
