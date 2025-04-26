# -*- coding: utf-8 -*-
import os
import json
import smtplib
import uuid
import logging
from logging.handlers import RotatingFileHandler
import datetime # Use standard datetime
from functools import wraps
from io import BytesIO

from flask import (
    Flask, render_template, request, redirect, send_file,
    session, url_for, flash, jsonify, Response
)
from flask_session import Session # Handles server-side sessions
from fpdf import FPDF
import stripe
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
# Required for datetime filter:
try:
    from babel.dates import format_datetime
    BABEL_INSTALLED = True
except ImportError:
    BABEL_INSTALLED = False


# --- Configuration ---
load_dotenv()

# --- Constants ---
DATA_DIR = os.getenv("DATA_DIR", "/data") # OnRender typically uses /data for persistent storage
PREBUILT_FILE = os.path.join(DATA_DIR, "prebuilts.json")
TICKETS_FILE = os.path.join(DATA_DIR, "tickets.json")
ORDERS_FILE = os.path.join(DATA_DIR, "orders.json")
RECEIPT_DIR = os.path.join(DATA_DIR, "receipts")
SECURITY_STATUS_FILE = os.path.join(DATA_DIR, "security_status.json") # File for security status
LOG_DIR = os.getenv("LOG_DIR", os.path.join(DATA_DIR, "logs")) # Store logs in persistent storage too
DEFAULT_IMAGE = 'static/images/default.jpg'

# --- Flask App Initialization ---
app = Flask(__name__, template_folder="app/templates", static_folder="app/static")

# --- Configuration Settings ---
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
if not app.config["SECRET_KEY"]:
    app.logger.critical("CRITICAL ERROR: SECRET_KEY is not set in environment variables!")
    # Potentially exit or raise error in production

# Session Configuration
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = os.path.join(DATA_DIR, "flask_session") # Persistent session storage
app.config["SESSION_PERMANENT"] = False
# You might want permanent admin sessions:
# app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(days=7)

# Stripe Configuration (Reads from environment variables)
app.config["STRIPE_SECRET_KEY"] = os.getenv("STRIPE_SECRET_KEY")
app.config["STRIPE_PUBLIC_KEY"] = os.getenv("STRIPE_PUBLIC_KEY")

# Application Behavior
app.config["YOUR_DOMAIN"] = os.getenv("DOMAIN", 'http://127.0.0.1:5000')
# Ensure DEBUG is False in production via environment variables
app.config["DEBUG"] = os.getenv("FLASK_DEBUG", "False").lower() in ("true", "1", "t")
app.config["FLASK_ENV"] = 'development' if app.config["DEBUG"] else 'production' # Set environment

# Email Configuration
app.config["EMAIL_ADDRESS"] = os.getenv("EMAIL_ADDRESS")
app.config["EMAIL_PASSWORD"] = os.getenv("EMAIL_PASSWORD") # Assumes Google App Password from screenshot

# Admin Credentials (Reads HASH from environment variable)
app.config["ADMIN_USERNAME"] = os.getenv("ADMIN_USERNAME", "admin")
# ***** IMPORTANT: Ensure ADMIN_PASSWORD environment variable contains the HASHED password *****
app.config["ADMIN_PASSWORD_HASH"] = os.getenv("ADMIN_PASSWORD")

if not app.config["ADMIN_PASSWORD_HASH"]:
     app.logger.critical("CRITICAL WARNING: ADMIN_PASSWORD environment variable is not set!")

# --- Initialize Extensions ---
Session(app)
if app.config["STRIPE_SECRET_KEY"]:
    stripe.api_key = app.config["STRIPE_SECRET_KEY"]
else:
    app.logger.error("STRIPE_SECRET_KEY is not set. Stripe integration will fail.")
    # In production, you might want to prevent startup if keys are missing


# --- Logging Setup ---
def setup_logging(app_instance):
    """Set up logging for the application"""
    # OnRender often captures stdout/stderr, but file logging is good too
    log_level = logging.DEBUG if app_instance.debug else logging.INFO
    # Basic console logging configured first
    logging.basicConfig(level=log_level, format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')

    # File logging to persistent storage
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        log_file = os.path.join(LOG_DIR, 'app.log')
        # Rotate logs: 5 files, 5MB each
        file_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=5)
        formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.INFO) # Log INFO and above to file
        app_instance.logger.addHandler(file_handler)
        # Avoid duplicate console logs if Werkzeug/Flask adds its own handler
        app_instance.logger.propagate = False
        app_instance.logger.info(f'File logging enabled at {log_file}')
    except Exception as e:
        app_instance.logger.error(f"Failed to set up file logging at {LOG_DIR}: {e}", exc_info=True)

    app_instance.logger.setLevel(log_level) # Set level for Flask's logger
    app_instance.logger.info('Application startup')
    app_instance.logger.info(f'Flask Environment: {app.config["FLASK_ENV"]}, Debug Mode: {app.config["DEBUG"]}')
    app_instance.logger.info(f'Domain configured: {app.config["YOUR_DOMAIN"]}')
    app_instance.logger.info(f'Data directory: {DATA_DIR}')

setup_logging(app) # Call logging setup early


# --- Context Processors & Filters ---
@app.context_processor
def inject_current_year():
    """Injects the current year into all templates."""
    return {'current_year': datetime.datetime.now().year}

if BABEL_INSTALLED:
    @app.template_filter('format_datetime')
    def _format_datetime(value, format='medium', locale='en_US'):
        """Formats an ISO datetime string using Babel."""
        if not value:
            return ''
        try:
            # Attempt to parse ISO format string
            dt_object = datetime.datetime.fromisoformat(value)
            return format_datetime(dt_object, format=format, locale=locale)
        except (ValueError, TypeError) as e:
            app.logger.warning(f"Could not format datetime '{value}': {e}")
            return value # Return original string if parsing/formatting fails
else:
    # Provide a dummy filter if Babel isn't installed
    @app.template_filter('format_datetime')
    def _format_datetime(value, format='medium', locale='en_US'):
        app.logger.warning("Babel not installed, cannot format datetime nicely.")
        return value # Return original string


# --- Data Handling Helpers (Unchanged from previous version) ---
# ... (load_json_data, save_json_data, load_prebuilts, etc. remain the same) ...
def load_json_data(filepath, default_data=[]):
    """Loads data from a JSON file, creating it if it doesn't exist."""
    try:
        if not os.path.exists(filepath):
            dirpath = os.path.dirname(filepath)
            if dirpath: # Ensure directory exists only if path includes one
                 os.makedirs(dirpath, exist_ok=True)
            with open(filepath, 'w') as f:
                json.dump(default_data, f, indent=4)
            app.logger.info(f"Created initial data file: {filepath}")
            return default_data
        else:
            with open(filepath, 'r') as f:
                content = f.read()
                if not content: return default_data
                return json.loads(content)
    except (IOError, json.JSONDecodeError, OSError) as e:
        app.logger.error(f"Error loading JSON data from {filepath}: {e}", exc_info=True)
        flash(f"Error accessing data file {os.path.basename(filepath)}. Please contact support.", "danger")
        return default_data

def save_json_data(filepath, data):
    """Saves data to a JSON file."""
    try:
        dirpath = os.path.dirname(filepath)
        if dirpath:
            os.makedirs(dirpath, exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4)
        return True
    except (IOError, OSError) as e:
        app.logger.error(f"Error saving JSON data to {filepath}: {e}", exc_info=True)
        flash(f"Error saving data file {os.path.basename(filepath)}. Please try again.", "danger")
        return False

def load_prebuilts():
    prebuilts = load_json_data(PREBUILT_FILE, default_data=[])
    for pc in prebuilts:
        pc.setdefault('image', DEFAULT_IMAGE)
        pc.setdefault('category', 'General Use')
        pc.setdefault('id', str(uuid.uuid4()))
    return prebuilts

def save_prebuilts(prebuilts_list): return save_json_data(PREBUILT_FILE, prebuilts_list)
def load_tickets(): return load_json_data(TICKETS_FILE, [])
def save_tickets(tickets_list): return save_json_data(TICKETS_FILE, tickets_list)
def load_orders(): return load_json_data(ORDERS_FILE, [])
def save_orders(orders_list): return save_json_data(ORDERS_FILE, orders_list)


# --- Initialization Logic (Unchanged) ---
# ... (initialize_data_files remains the same) ...
def initialize_data_files():
    app.logger.info("Initializing data directories and files...")
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        os.makedirs(app.config["SESSION_FILE_DIR"], exist_ok=True)
        os.makedirs(RECEIPT_DIR, exist_ok=True)
        os.makedirs(LOG_DIR, exist_ok=True) # Ensure log dir exists too
        app.logger.info(f"Ensured directories exist: {DATA_DIR}, {app.config['SESSION_FILE_DIR']}, {RECEIPT_DIR}, {LOG_DIR}")

        if not os.path.exists(PREBUILT_FILE) or os.path.getsize(PREBUILT_FILE) == 0:
            app.logger.info(f"Prebuilt file {PREBUILT_FILE} empty/missing. Creating defaults.")
            default_prebuilts = [
                { "id": str(uuid.uuid4()), "name": "Gamer Beast 5000", "price": 1499.99, "description": "A top-tier rig with RTX 4070 Super and Ryzen 7 7800X3D.", "image": "static/images/default.jpg", "category": "Gaming" },
                { "id": str(uuid.uuid4()), "name": "Code Cruncher Pro", "price": 899.99, "description": "Perfect for developers, preloaded with Linux and 32GB RAM.", "image": "static/images/default.jpg", "category": "Programming" }
            ]
            save_prebuilts(default_prebuilts)

        load_tickets()
        load_orders()
        app.logger.info("Data file initialization check complete.")

    except Exception as e:
        app.logger.error(f"Failed during data file initialization: {e}", exc_info=True)

initialize_data_files()

# --- Decorators (Unchanged) ---
# ... (admin_required remains the same) ...
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session or not session['admin_logged_in']:
            flash("Admin access required. Please log in.", "warning")
            return redirect(url_for('admin_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# --- Email Helper (Unchanged) ---
# ... (send_email remains the same, still basic text implementation) ...
def send_email(to_address, subject, body, attachment_path=None, attachment_filename=None):
    sender = app.config.get("EMAIL_ADDRESS")
    password = app.config.get("EMAIL_PASSWORD") # Assumes Google App Password
    if not sender or not password:
        app.logger.error("Email address or password not configured. Cannot send email.")
        return False
    message = f"Subject: {subject}\nFrom: {sender}\nTo: {to_address}\n\n{body}"
    try:
        # Using Gmail SMTP with SSL
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(sender, password)
            smtp.sendmail(from_addr=sender, to_addrs=to_address, msg=message.encode('utf-8'))
        app.logger.info(f"Email sent successfully to {to_address}")
        return True
    except smtplib.SMTPAuthenticationError:
        app.logger.error(f"Email authentication failed for {sender}. Check credentials/App Password and Gmail security settings.")
        flash("Failed to send email due to authentication error.", "danger")
        return False
    except Exception as e:
        app.logger.error(f"Failed to send email to {to_address}: {e}", exc_info=True)
        flash(f"Failed to send email: {e}.", "danger")
        return False

# --- Routes ---

# --- Public Routes (Unchanged) ---
@app.route('/')
def index(): return render_template('home.html')

@app.route('/terms')
def terms(): return render_template('terms.html') # Ensure terms.html exists

@app.route('/prebuilts')
def prebuilts():
    pcs = load_prebuilts()
    categories = sorted(list(set(pc.get('category', 'General Use') for pc in pcs)))
    categorized_pcs = {cat: [pc for pc in pcs if pc.get('category', 'General Use') == cat] for cat in categories}
    return render_template("prebuilts.html", categorized_pcs=categorized_pcs, categories=categories)

@app.route('/custom')
def custom(): return render_template('custom.html')


# --- Support Route (Unchanged) ---
@app.route('/support', methods=['GET', 'POST'])
def support_ticket():
    # ... (route logic remains the same) ...
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        issue = request.form.get('issue', '').strip()
        errors = []
        if not name: errors.append("Name is required.")
        if not email: errors.append("Email is required.")
        if not issue: errors.append("Issue description is required.")
        if errors:
            for error in errors: flash(error, "warning")
            return render_template("support.html", name=name, email=email, issue=issue)

        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ticket_id = str(uuid.uuid4())
        ticket = { "id": ticket_id, "name": name, "email": email, "issue": issue, "timestamp": timestamp, "status": "open" }
        tickets = load_tickets()
        tickets.append(ticket)
        if save_tickets(tickets):
            app.logger.info(f"New support ticket: ID {ticket_id} by {name}")
            subject = f"New Support Ticket #{ticket_id[:8]} from {name}"
            body = f"New ticket submitted:\n\nName: {name}\nEmail: {email}\nIssue:\n{issue}\n\nTime: {timestamp}"
            send_email(app.config["EMAIL_ADDRESS"], subject, body)
            flash(f"Support ticket submitted successfully. Your ticket ID is {ticket_id}.", "success")
            return redirect(url_for('support_ticket'))
        else:
            return render_template("support.html", name=name, email=email, issue=issue)
    return render_template("support.html")


# --- Checkout Routes (Unchanged) ---
@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    # ... (route logic remains the same) ...
    item_name = request.form.get('item')
    amount_str = request.form.get('amount')
    customer_email = request.form.get('email')
    if not item_name or not amount_str:
        flash("Missing item/amount.", "danger"); return redirect(request.referrer or url_for('prebuilts'))
    try:
        amount = float(amount_str)
        if amount <= 0: raise ValueError("Amount must be positive.")
        amount_cents = int(round(amount * 100))
    except ValueError:
        flash("Invalid amount.", "danger"); return redirect(request.referrer or url_for('prebuilts'))
    if not customer_email: # Basic email check
        flash("Email is required.", "danger"); return redirect(request.referrer or url_for('prebuilts'))

    order_id = str(uuid.uuid4())
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    session['pending_order_details'] = { "item": item_name, "amount": amount, "order_id": order_id, "email": customer_email, "timestamp": timestamp }
    app.logger.info(f"Creating Stripe session for pending Order ID: {order_id}")
    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{'price_data': {'currency': 'usd', 'product_data': {'name': item_name,}, 'unit_amount': amount_cents,}, 'quantity': 1,}],
            mode='payment',
            success_url=url_for('thank_you', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=url_for('prebuilts', _external=True),
            customer_email=customer_email,
            metadata={'order_id': order_id, 'customer_email': customer_email}
        )
        return redirect(checkout_session.url, code=303)
    except stripe.error.StripeError as e:
        err_msg = e.user_message or str(e)
        app.logger.error(f"Stripe API error for {order_id}: {err_msg}", exc_info=True)
        flash(f"Payment error: {err_msg}. Please try again.", "danger")
        session.pop('pending_order_details', None)
        return redirect(request.referrer or url_for('prebuilts'))
    except Exception as e:
        app.logger.error(f"Checkout session error for {order_id}: {e}", exc_info=True)
        flash("Checkout error. Please try again.", "danger")
        session.pop('pending_order_details', None)
        return redirect(request.referrer or url_for('prebuilts'))

@app.route('/thankyou')
def thank_you():
    # ... (route logic remains the same - including retrieving session, saving order, generating PDF, sending email) ...
    stripe_session_id = request.args.get('session_id')
    if not stripe_session_id:
        flash("Invalid access.", "warning"); return redirect(url_for('index'))
    app.logger.info(f"Thank you page accessed: {stripe_session_id}")
    try:
        checkout_session = stripe.checkout.Session.retrieve(stripe_session_id)
        payment_status = checkout_session.payment_status
        order_id_from_stripe = checkout_session.metadata.get('order_id')
        app.logger.info(f"Stripe session {stripe_session_id} status: {payment_status}, Order ID: {order_id_from_stripe}")
        if payment_status != "paid":
             flash("Payment not successful.", "warning"); return redirect(url_for('index'))

        order_data = session.pop('pending_order_details', None)
        if not order_data or order_data.get('order_id') != order_id_from_stripe:
            app.logger.warning(f"Session data mismatch/missing for {stripe_session_id}. Reconstructing.")
            order_data = {
                "item": checkout_session.line_items.data[0].description if checkout_session.line_items else "Item",
                "amount": checkout_session.amount_total / 100.0,
                "order_id": order_id_from_stripe or f"stripe_{stripe_session_id}",
                "email": checkout_session.customer_details.email,
                "timestamp": datetime.datetime.fromtimestamp(checkout_session.created).strftime('%Y-%m-%d %H:%M:%S'),
                "stripe_session_id": stripe_session_id
            }
        else:
             order_data['stripe_session_id'] = stripe_session_id

        orders = load_orders()
        if not any(o.get('stripe_session_id') == stripe_session_id for o in orders):
            orders.append(order_data)
            if save_orders(orders): app.logger.info(f"Saved Order ID: {order_data['order_id']}")
            else: app.logger.error(f"CRITICAL: Failed to save confirmed Order ID: {order_data['order_id']}")
        else: app.logger.warning(f"Order {order_data['order_id']} already saved. Skipping duplicate.")

        pdf_filename = f"receipt_{order_data['order_id']}.pdf"
        pdf_filepath = os.path.join(RECEIPT_DIR, pdf_filename)
        try:
            pdf = FPDF()
            pdf.add_page(); pdf.set_font("Arial", 'B', 16); pdf.cell(0, 10, txt="John's Easy Tech - Purchase Receipt", ln=True, align='C')
            pdf.ln(10); pdf.set_font("Arial", size=12)
            pdf.cell(40, 10, txt="Order #:"); pdf.cell(0, 10, txt=order_data['order_id'], ln=True)
            pdf.cell(40, 10, txt="Item:"); pdf.cell(0, 10, txt=order_data['item'], ln=True)
            pdf.cell(40, 10, txt="Amount Paid:"); pdf.cell(0, 10, txt=f"${order_data['amount']:.2f} USD", ln=True)
            pdf.cell(40, 10, txt="Date:"); pdf.cell(0, 10, txt=order_data['timestamp'], ln=True)
            pdf.cell(40, 10, txt="Paid By:"); pdf.cell(0, 10, txt=order_data['email'], ln=True)
            pdf.ln(10); pdf.set_font("Arial", 'I', 10); terms_url = url_for('terms', _external=True)
            pdf.multi_cell(0, 5, txt=f"Thank you! By completing this order, you agreed to Terms and Conditions at: {terms_url}")
            pdf.output(pdf_filepath, "F")
            app.logger.info(f"Generated PDF receipt: {pdf_filepath}")
            session['last_receipt_path'] = pdf_filepath
            session['last_receipt_filename'] = pdf_filename
        except Exception as pdf_err:
             app.logger.error(f"Failed PDF generation for {order_data['order_id']}: {pdf_err}", exc_info=True)
             session.pop('last_receipt_path', None); session.pop('last_receipt_filename', None)
             flash("Payment successful, but receipt generation failed. Contact support.", "warning")

        email_subject = f"Your Order Receipt - #{order_data['order_id']}"
        email_body = f"Thank you!\n\nOrder #: {order_data['order_id']}\nItem: {order_data['item']}\nAmount: ${order_data['amount']:.2f}\nDate: {order_data['timestamp']}\n\nTerms: {url_for('terms', _external=True)}"
        send_email(order_data['email'], email_subject, email_body) # Still sending text only

        return render_template('thankyou.html', order=order_data)
    except stripe.error.StripeError as e:
        err_msg = e.user_message or str(e)
        app.logger.error(f"Stripe verification error for {stripe_session_id}: {err_msg}", exc_info=True)
        flash(f"Payment verification error: {err_msg}. Contact support.", "danger")
        session.pop('pending_order_details', None)
        return redirect(url_for('index'))
    except Exception as e:
        app.logger.error(f"Thank you page error for {stripe_session_id}: {e}", exc_info=True)
        session.pop('pending_order_details', None)
        flash("Unexpected error after payment. Contact support.", "danger")
        return redirect(url_for('index'))

@app.route('/download-receipt')
def download_receipt():
    # ... (route logic remains the same) ...
    pdf_filepath = session.get('last_receipt_path')
    pdf_filename = session.get('last_receipt_filename', 'receipt.pdf')
    if pdf_filepath and os.path.exists(pdf_filepath):
        try:
            app.logger.info(f"Serving receipt download: {pdf_filepath}")
            return send_file(pdf_filepath, as_attachment=True, download_name=pdf_filename)
        except Exception as e:
            app.logger.error(f"Error sending receipt file {pdf_filepath}: {e}", exc_info=True)
            flash("Could not download receipt.", "danger"); return redirect(request.referrer or url_for('index'))
    else:
        app.logger.warning(f"Receipt download failed: Path='{pdf_filepath}'")
        flash("Receipt not found or session expired.", "warning"); return redirect(url_for('index'))

# --- Admin Routes ---

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Handles admin login using hashed password check."""
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password_from_form = request.form.get('password')
        stored_hash = app.config.get("ADMIN_PASSWORD_HASH") # Get HASH from config

        # --- Secure Password Verification ---
        login_valid = False
        if not stored_hash:
             app.logger.error("ADMIN_PASSWORD (hash) is not configured in environment variables!")
             flash("Server configuration error. Login disabled.", "danger")
        elif username == app.config.get("ADMIN_USERNAME") and password_from_form:
            try:
                # Compare the hash from .env with the password provided in the form
                if check_password_hash(stored_hash, password_from_form):
                    login_valid = True
                else:
                    app.logger.warning(f"Admin login failed (Password mismatch) for username: {username}")
            except Exception as e:
                # Handle potential errors during hash checking itself
                app.logger.error(f"Error during password hash check: {e}", exc_info=True)
                flash("An error occurred during login. Please try again.", "danger")
        else:
             # Case where username is wrong or password field was empty
             app.logger.warning(f"Admin login attempt failed (Invalid username/empty password) for username: {username}")

        # --- Handle Login Result ---
        if login_valid:
            session.clear() # Prevent session fixation: clear old session
            session['admin_logged_in'] = True
            session.permanent = True # Optional: Make admin session last longer if lifetime set
            app.logger.info(f"Admin login successful for user: {username}")
            next_url = request.args.get('next')
            # Basic open redirect protection
            if next_url and not next_url.startswith(('/', url_for('index'))):
                 app.logger.warning(f"Invalid 'next' URL during login: {next_url}")
                 next_url = None # Ignore invalid next URL
            return redirect(next_url or url_for('admin_dashboard'))
        else:
            # Avoid specific error messages like "wrong password"
            if stored_hash: # Only flash general error if config was okay
                flash('Invalid username or password.', 'danger')

    # GET request or failed/invalid POST
    return render_template('admin/login.html')

@app.route('/admin/edit_product/<product_id>', methods=['GET'])
@admin_required
def admin_edit_product_form(product_id):
    """Displays the form to edit an existing product."""
    prebuilts = load_prebuilts()
    product_to_edit = next((p for p in prebuilts if p.get('id') == product_id), None)

    if not product_to_edit:
        flash("Product not found.", "danger")
        return redirect(url_for('admin_view_products'))

    # Get categories for the dropdown
    categories = sorted(list(set(pc.get('category', 'General Use') for pc in prebuilts)))

    return render_template('admin/edit_product.html', product=product_to_edit, categories=categories)


@app.route('/admin/edit_product/<product_id>', methods=['POST'])
@admin_required
def admin_update_product(product_id):
    """Updates an existing product's details."""
    # TODO: Add CSRF check if using Flask-WTF
    prebuilts = load_prebuilts()
    product_index = next((i for i, p in enumerate(prebuilts) if p.get('id') == product_id), -1)

    if product_index == -1:
        flash("Product not found.", "danger")
        return redirect(url_for('admin_view_products'))

    # TODO: Add Flask-WTF validation here for better handling
    try:
        # Get current product data
        product_data = prebuilts[product_index]

        # Get updated data from form
        name = request.form.get('name', product_data.get('name', '')).strip()
        description = request.form.get('description', product_data.get('description', '')).strip()
        price_str = request.form.get('price', str(product_data.get('price', '0'))).strip()
        image = request.form.get('image', product_data.get('image', '')).strip()
        category = request.form.get('category', product_data.get('category', 'General Use')).strip()

        # Basic Manual Validation (replace/enhance with WTForms)
        errors = []
        if not name: errors.append("Product name is required.")
        if not description: errors.append("Product description is required.")
        if not category: errors.append("Product category is required.")
        price = product_data.get('price', 0.0) # Default to old price if conversion fails
        try:
             updated_price = float(price_str)
             if updated_price < 0:
                 errors.append("Price cannot be negative.")
             else:
                 price = updated_price # Only update if valid
        except ValueError:
             errors.append("Invalid price format. Please enter a number.")

        if errors:
            for error in errors:
                flash(error, "warning")
            # Re-render the edit form with current (potentially invalid) data
            # Need to reconstruct the 'product' dict with submitted values to refill form
            failed_product_data = product_data.copy() # Start with original
            failed_product_data.update({ # Overwrite with submitted values
                 'name': name, 'description': description, 'price': price_str, # Keep price as string for form
                 'image': image, 'category': category
            })
            categories = sorted(list(set(pc.get('category', 'General Use') for pc in prebuilts)))
            return render_template('admin/edit_product.html', product=failed_product_data, categories=categories)


        # Update product details in the list
        prebuilts[product_index]['name'] = name
        prebuilts[product_index]['description'] = description
        prebuilts[product_index]['price'] = price
        prebuilts[product_index]['image'] = image or DEFAULT_IMAGE # Use default if image cleared
        prebuilts[product_index]['category'] = category

        # Save the updated list back to JSON
        if save_prebuilts(prebuilts):
            flash(f"Product '{name}' updated successfully.", "success")
            app.logger.info(f"Admin updated product ID: {product_id} (Name: {name})")
        else:
            # Error message flashed by save_prebuilts
            pass # Redirect anyway

        return redirect(url_for('admin_view_products'))

    except Exception as e:
        app.logger.error(f"Update product {product_id} failed unexpectedly: {e}", exc_info=True)
        flash("An unexpected error occurred when updating the product.", "danger")
        return redirect(url_for('admin_view_products'))



@app.route('/admin/logout')
@admin_required
def admin_logout():
    # ... (route logic remains the same) ...
    username = app.config.get("ADMIN_USERNAME", "admin")
    session.pop('admin_logged_in', None)
    session.clear() # Clear everything
    flash('You have been logged out.', 'success')
    app.logger.info(f"Admin logout: {username}")
    return redirect(url_for('admin_login'))

# --- Admin Dashboard & Content Management (Unchanged logic, uses new templates) ---
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    # ... (logic remains the same, renders updated template) ...
    products = load_prebuilts()
    tickets = load_tickets()
    orders = load_orders()
    open_ticket_count = sum(1 for t in tickets if t.get('status') == 'open')
    return render_template("admin/dashboard.html", products=products, tickets=tickets, orders=orders[-10:], open_ticket_count=open_ticket_count)

@app.route('/admin/products', methods=['GET'])
@admin_required
def admin_view_products():
    # ... (logic remains the same, renders updated template) ...
    prebuilts = load_prebuilts()
    categories = sorted(list(set(pc.get('category', 'General Use') for pc in prebuilts)))
    categorized_pcs = {cat: [pc for pc in prebuilts if pc.get('category', 'General Use') == cat] for cat in categories}
    return render_template('admin/products.html', categorized_pcs=categorized_pcs, categories=categories)


@app.route('/admin/add_product', methods=['POST'])
@admin_required
def admin_add_product():
    # ... (logic remains the same, uses form data from updated template) ...
    # TODO: Add Flask-WTF validation
    try:
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        price_str = request.form.get('price', '0').strip()
        image = request.form.get('image', '').strip()
        category = request.form.get('category', 'General Use').strip()

        errors = []
        if not name: errors.append("Name required.")
        if not description: errors.append("Description required.")
        if not category: errors.append("Category required.")
        price = 0.0
        try: price = float(price_str); assert price >= 0
        except (ValueError, AssertionError): errors.append("Invalid price.")

        if errors:
            for error in errors: flash(error, "warning")
            return redirect(url_for('admin_view_products'))

        new_product = { "id": str(uuid.uuid4()), "name": name, "description": description, "price": price, "image": image or DEFAULT_IMAGE, "category": category }
        prebuilts = load_prebuilts()
        prebuilts.append(new_product)
        if save_prebuilts(prebuilts):
            flash(f"Product '{name}' added.", "success"); app.logger.info(f"Admin added product: {name}")
        return redirect(url_for('admin_view_products'))
    except Exception as e:
        app.logger.error(f"Add product failed: {e}", exc_info=True)
        flash("Error adding product.", "danger"); return redirect(url_for('admin_view_products'))

@app.route('/admin/delete_product/<product_id>', methods=['POST'])
@admin_required
def admin_delete_product(product_id):
    # ... (logic remains the same, uses product_id) ...
    # TODO: Add CSRF check
    try:
        prebuilts = load_prebuilts()
        initial_len = len(prebuilts)
        prebuilts_filtered = [p for p in prebuilts if p.get('id') != product_id]
        if len(prebuilts_filtered) < initial_len:
            if save_prebuilts(prebuilts_filtered):
                name = next((p.get('name','?') for p in prebuilts if p.get('id') == product_id),'?')
                flash(f"Product '{name}' deleted.", "success"); app.logger.info(f"Admin deleted product ID: {product_id}")
            # else: error flashed by save_prebuilts
        else: flash("Product not found.", "warning"); app.logger.warning(f"Delete failed: Product ID {product_id} not found.")
        return redirect(url_for('admin_view_products'))
    except Exception as e:
        app.logger.error(f"Error deleting product {product_id}: {e}", exc_info=True)
        flash("Error deleting product.", "danger"); return redirect(url_for('admin_view_products'))


@app.route('/admin/tickets', methods=['GET'])
@admin_required
def admin_view_tickets():
    # ... (logic remains the same, renders updated template) ...
    tickets = load_tickets()
    ticket_status_filter = request.args.get("status", "all").lower()
    search_query = request.args.get("search", "").strip().lower()
    filtered_tickets = tickets
    if ticket_status_filter == "open": filtered_tickets = [t for t in filtered_tickets if t.get('status') == 'open']
    elif ticket_status_filter == "closed": filtered_tickets = [t for t in filtered_tickets if t.get('status') == 'closed']
    if search_query:
         filtered_tickets = [ t for t in filtered_tickets if search_query in t.get("name", "").lower() or search_query in t.get("email", "").lower() or search_query in t.get("issue", "").lower() or search_query in t.get("id", "").lower() ]
    return render_template('admin/tickets.html', tickets=filtered_tickets, ticket_status_filter=ticket_status_filter, search_query=search_query)


@app.route('/admin/close_ticket/<ticket_id>', methods=['POST'])
@admin_required
def admin_close_ticket(ticket_id):
    # ... (logic remains the same, uses ticket_id) ...
    # TODO: Add CSRF check
    try:
        tickets = load_tickets()
        ticket_found = False; ticket_updated = False
        for ticket in tickets:
            if ticket.get("id") == ticket_id:
                ticket_found = True
                if ticket.get("status") != "closed":
                    ticket["status"] = "closed"
                    if save_tickets(tickets):
                        flash(f"Ticket {ticket_id[:8]} closed.", "success"); app.logger.info(f"Admin closed ticket ID: {ticket_id}")
                        ticket_updated = True
                    # else: error flashed by save_tickets
                else:
                    flash(f"Ticket {ticket_id[:8]} already closed.", "info"); ticket_updated = True
                break
        if not ticket_found: flash("Ticket not found.", "warning"); app.logger.warning(f"Close failed: Ticket ID {ticket_id} not found.")
        status_filter = request.form.get('status_filter', 'all')
        search_query = request.form.get('search_query', '')
        return redirect(url_for('admin_view_tickets', status=status_filter, search=search_query))
    except Exception as e:
        app.logger.error(f"Error closing ticket {ticket_id}: {e}", exc_info=True)
        flash("Error closing ticket.", "danger"); return redirect(url_for('admin_view_tickets'))


@app.route('/admin/test-email', methods=['POST'])
@admin_required
def admin_test_email():
    # ... (logic remains the same) ...
    # TODO: Add CSRF check
    admin_email = app.config.get('EMAIL_ADDRESS')
    if not admin_email: flash("Admin email not configured.", "danger"); return redirect(url_for('admin_dashboard'))
    subject = f"Test Email - {app.config['YOUR_DOMAIN']} Admin"
    body = f"Test email sent from admin panel.\nTime: {datetime.datetime.now()}"
    if send_email(admin_email, subject, body):
        flash(f'Test email sent to {admin_email}.', 'success'); app.logger.info("Admin test email sent.")
    else: app.logger.error("Admin test email failed.") # Error flashed by helper
    return redirect(url_for('admin_dashboard'))


# --- Security Check Routes (Basic Implementation) ---
def check_security_status():
    """Performs basic security checks and returns status dict."""
    app.logger.info("Running security checks...")
    status = { 'timestamp': datetime.datetime.now().isoformat(), 'checks_performed': [] }
    checks = status['checks_performed']

    # 1. Debug Mode Check
    is_debug = app.config['DEBUG']
    checks.append({ 'name': 'Debug Mode', 'status': 'WARNING' if is_debug else 'OK', 'details': f"Debug mode is {'ON' if is_debug else 'OFF'}." + (" Should be OFF in production." if is_debug else "") })

    # 2. Admin Password Check (Checks if hash exists)
    has_hash = bool(app.config.get('ADMIN_PASSWORD_HASH'))
    checks.append({ 'name': 'Admin Password Hash', 'status': 'OK' if has_hash else 'CRITICAL', 'details': "Checks if ADMIN_PASSWORD env var is set." + (" Hash should be stored, not plaintext." if has_hash else " Env var MUST be set to a password HASH.") })

    # 3. Secret Key Check
    secret_key = app.config.get('SECRET_KEY')
    is_weak_key = not secret_key or secret_key == 'temporary-insecure-key-for-dev-only'
    checks.append({ 'name': 'Secret Key Strength', 'status': 'CRITICAL' if is_weak_key else 'OK', 'details': "Checks if SECRET_KEY is set and not a known weak default." })

    # 4. Email Config Check
    email_ok = bool(app.config.get('EMAIL_ADDRESS') and app.config.get('EMAIL_PASSWORD'))
    checks.append({ 'name': 'Email Configuration', 'status': 'OK' if email_ok else 'WARNING', 'details': "Checks if EMAIL_ADDRESS and EMAIL_PASSWORD are set." })

    # 5. Stripe Keys Check (Warn if using test keys in production env)
    is_prod_env = app.config['FLASK_ENV'] == 'production'
    using_test_keys = app.config.get('STRIPE_SECRET_KEY','').startswith('sk_test_')
    stripe_status = 'OK'
    stripe_details = "Checks if Stripe keys are set."
    if not app.config.get('STRIPE_SECRET_KEY'):
        stripe_status = 'WARNING'
        stripe_details += " Secret key missing!"
    elif is_prod_env and using_test_keys:
        stripe_status = 'WARNING'
        stripe_details += " Using TEST keys in production environment!"
    elif not is_prod_env and not using_test_keys and app.config.get('STRIPE_SECRET_KEY'):
         stripe_status = 'INFO' # Using Live keys in dev is okay but maybe noteworthy
         stripe_details += " Using LIVE keys in development environment."
    checks.append({ 'name': 'Stripe Keys', 'status': stripe_status, 'details': stripe_details })

    # Calculate Overall Status
    if any(c['status'] == 'CRITICAL' for c in checks): status['overall_status'] = 'CRITICAL'
    elif any(c['status'] == 'WARNING' for c in checks): status['overall_status'] = 'WARNING'
    else: status['overall_status'] = 'OK'

    # Save status to file
    if not save_json_data(SECURITY_STATUS_FILE, status):
         app.logger.error("Failed to save security status to file!")
         # Maybe flash an error here too
    return status

def get_last_security_status():
    """Loads the last saved security status from JSON file."""
    app.logger.info(f"Fetching last security status from {SECURITY_STATUS_FILE}")
    status_data = load_json_data(SECURITY_STATUS_FILE, default_data=None)
    if status_data is None:
        # load_json_data failed (error already logged/flashed) or file doesn't exist yet
        return {'message': 'Security status file not found or unreadable.', 'timestamp': None}
    elif not isinstance(status_data, dict) or 'timestamp' not in status_data:
         app.logger.warning(f"Invalid format in security status file: {SECURITY_STATUS_FILE}")
         return {'message': 'Security status file is invalid.', 'timestamp': None}
    return status_data


@app.route('/admin/security-check', methods=['POST'])
@admin_required
def run_security_check():
    """Runs security checks and redirects to status page."""
    # TODO: Add CSRF check
    try:
        status = check_security_status() # This now saves the status too
        if status.get('overall_status') == 'CRITICAL':
             flash("CRITICAL security issues found!", "danger")
        elif status.get('overall_status') == 'WARNING':
             flash("Security check found WARNINGS.", "warning")
        else:
             flash("Security check completed.", "success")
        app.logger.info(f"Admin triggered security check. Overall: {status.get('overall_status')}")
    except Exception as e:
        app.logger.error(f"Security check run failed: {e}", exc_info=True)
        flash("Error running security checks.", "danger")
    # Redirect to the status page to view results
    return redirect(url_for('get_security_status_route'))


@app.route('/admin/security-status')
@admin_required
def get_security_status_route():
    """Displays the last known security status."""
    try:
        status = get_last_security_status()
        return render_template('admin/security_status.html', status=status)
    except Exception as e:
        app.logger.error(f"Failed to get security status page: {e}", exc_info=True)
        flash("Error retrieving security status.", "danger")
        return redirect(url_for('admin_dashboard'))


# --- Error Handlers (Unchanged) ---
# ... (Error handlers 401, 403, 404, 500, Exception remain the same) ...
@app.errorhandler(404)
def not_found_error(error):
    app.logger.warning(f'Not Found: {request.path} (Referrer: {request.referrer}, IP: {request.remote_addr})')
    return render_template('error.html', error_code=404, error_message="Sorry, the page you are looking for doesn't exist."), 404

@app.errorhandler(403)
def forbidden_error(error):
    app.logger.warning(f'Forbidden access attempt: {request.path} by {request.remote_addr}')
    return render_template('error.html', error_code=403, error_message="Sorry, you don't have permission to access this page."), 403

@app.errorhandler(401)
def unauthorized_error(error):
    app.logger.warning(f'Unauthorized access attempt: {request.path} from {request.remote_addr}')
    flash("You need to be logged in to access this page.", "warning")
    return redirect(url_for('admin_login', next=request.url)) if request.path.startswith('/admin') else redirect(url_for('index'))

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f'Internal Server Error on path {request.path}: {error}', exc_info=True)
    message = "An unexpected internal error occurred. We have been notified."
    if app.debug: message = f"Internal Server Error: {error}"
    return render_template('error.html', error_code=500, error_message=message), 500

@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(f'Unhandled Exception on path {request.path}: {e}', exc_info=True)
    message = "An unexpected error occurred."
    if app.debug: message = f"Unhandled Exception: {e}"
    return render_template('error.html', error_code=500, error_message=message), 500

# --- Main Execution ---
# This block is mainly for local development.
# OnRender will typically use a command like 'gunicorn app:app' specified in its settings.
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    # Debug mode is controlled by FLASK_DEBUG env var
    # Host '0.0.0.0' is needed for OnRender/Docker, '127.0.0.1' for local only.
    host = '0.0.0.0'
    app.run(host=host, port=port) # Debug is set via app.config['DEBUG']