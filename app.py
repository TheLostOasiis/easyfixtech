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
CUSTOM_REQUESTS_FILE = os.path.join(DATA_DIR, "custom_requests.json") # <<< ADDED
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
     app.logger.info(f'Data directory: {DATA_DIR}')

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


# --- Data Handling Helpers ---
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
                 if not content: return default_data # Handle empty file case
                 return json.loads(content)
     except (IOError, json.JSONDecodeError, OSError) as e:
         app.logger.error(f"Error loading JSON data from {filepath}: {e}", exc_info=True)
         flash(f"Error accessing data file {os.path.basename(filepath)}. Please contact support.", "danger")
         return default_data # Return default on error

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

# Specific Loaders/Savers
def load_prebuilts():
    prebuilts = load_json_data(PREBUILT_FILE, default_data=[])
    # Ensure essential keys exist with defaults
    for pc in prebuilts:
        pc.setdefault('image', DEFAULT_IMAGE)
        pc.setdefault('category', 'General Use')
        pc.setdefault('id', str(uuid.uuid4())) # Add ID if missing
    return prebuilts

def save_prebuilts(prebuilts_list): return save_json_data(PREBUILT_FILE, prebuilts_list)
def load_tickets(): return load_json_data(TICKETS_FILE, [])
def save_tickets(tickets_list): return save_json_data(TICKETS_FILE, tickets_list)
def load_orders(): return load_json_data(ORDERS_FILE, [])
def save_orders(orders_list): return save_json_data(ORDERS_FILE, orders_list)

# <<< ADDED: Custom Request Load/Save Helpers >>>
def load_custom_requests(): return load_json_data(CUSTOM_REQUESTS_FILE, [])
def save_custom_requests(requests_list): return save_json_data(CUSTOM_REQUESTS_FILE, requests_list)


# --- Initialization Logic ---
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

        # Ensure other files exist by calling their loaders
        load_tickets()
        load_orders()
        load_custom_requests() # <<< UPDATED: Ensure custom requests file exists
        app.logger.info("Data file initialization check complete.")

    except Exception as e:
        app.logger.error(f"Failed during data file initialization: {e}", exc_info=True)

initialize_data_files() # Call initialization after helpers are defined


# --- Decorators ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session or not session['admin_logged_in']:
            flash("Admin access required. Please log in.", "warning")
            return redirect(url_for('admin_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# --- Email Helper ---
def send_email(to_address, subject, body, attachment_path=None, attachment_filename=None):
    # Note: This uses basic smtplib with Gmail. For production, consider Flask-Mail
    # Also, attachment logic is not implemented here.
    sender = app.config.get("EMAIL_ADDRESS")
    password = app.config.get("EMAIL_PASSWORD") # Assumes Google App Password
    if not sender or not password:
        app.logger.error("Email address or password not configured. Cannot send email.")
        return False

    # Basic email structure (plain text)
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

# --- Public Routes ---
@app.route('/')
def index():
    return render_template('home.html')

@app.route('/terms')
def terms():
    # Ensure templates/terms.html exists or create it
    return render_template('terms.html')

@app.route('/prebuilts')
def prebuilts():
    pcs = load_prebuilts()
    # Create categories dynamically and sort them
    categories = sorted(list(set(pc.get('category', 'General Use') for pc in pcs)))
    # Group PCs by category
    categorized_pcs = {cat: [pc for pc in pcs if pc.get('category', 'General Use') == cat] for cat in categories}
    return render_template("prebuilts.html", categorized_pcs=categorized_pcs, categories=categories)

# --- UPDATED: /custom route handles GET and POST ---
@app.route('/custom', methods=['GET', 'POST'])
def custom_build_request():
    if request.method == 'POST':
        # --- 1. Receive Form Data ---
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        budget = request.form.get('budget') # Keep as selected value
        primary_use = request.form.get('primary_use')
        cpu_pref = request.form.get('cpu_pref', 'No Preference')
        gpu_pref = request.form.get('gpu_pref', 'No Preference')
        ram_amount = request.form.get('ram_amount', 'No Preference')
        details = request.form.get('details', '').strip()
        os_pref = request.form.get('os_pref', 'Windows 11 Home')
        terms_agree = request.form.get('terms_agree') # Value is 'yes' if checked

        # --- 2. Server-Side Validation (Essential!) ---
        errors = []
        if not name:
            errors.append("Name is required.")
        if not email: # Consider adding better email format validation
            errors.append("Email is required.")
        if not budget:
            errors.append("Budget range is required.")
        if not primary_use:
            errors.append("Primary use case is required.")
        if not terms_agree:
            errors.append("You must agree to the terms and conditions.")
        # Add more specific validation if needed (e.g., budget format)

        if errors:
            for error in errors:
                flash(error, 'warning') # Use flash to show errors
            # Re-render form, passing back submitted data to repopulate fields
            app.logger.warning(f"Custom build form validation failed: {errors}")
            return render_template('custom.html',
                                   name=name, email=email, budget=budget,
                                   primary_use=primary_use, cpu_pref=cpu_pref,
                                   gpu_pref=gpu_pref, ram_amount=ram_amount,
                                   details=details, os_pref=os_pref)

        # --- 3. Process the Valid Request ---
        timestamp = datetime.datetime.now().isoformat() # Use ISO format for consistency
        request_id = str(uuid.uuid4())
        custom_request_data = {
            "id": request_id,
            "timestamp": timestamp,
            "status": "new", # Add a status field
            "name": name,
            "email": email,
            "budget": budget,
            "primary_use": primary_use,
            "cpu_pref": cpu_pref,
            "gpu_pref": gpu_pref,
            "ram_amount": ram_amount,
            "os_pref": os_pref,
            "details": details
        }

        # Attempt to save to JSON file
        requests_list = load_custom_requests()
        requests_list.append(custom_request_data)

        if save_custom_requests(requests_list):
            app.logger.info(f"Saved new custom build request ID: {request_id} from {name}")

            # Attempt to send email notification
            admin_email = app.config.get('EMAIL_ADDRESS')
            if admin_email:
                subject = f"New Custom Build Request - {name} ({request_id[:8]})"
                body = f"""
New Custom Build Request Received:

Request ID: {request_id}
Time: {timestamp}
Name: {name}
Email: {email}
Budget: {budget}
Primary Use: {primary_use}
CPU Preference: {cpu_pref}
GPU Preference: {gpu_pref}
RAM Amount: {ram_amount}
OS Preference: {os_pref}

Details / Notes:
-----------------
{details}
-----------------
"""
                send_email(admin_email, subject, body) # Use your existing email function
            else:
                app.logger.warning("Admin email not configured, skipping notification for custom request.")

            flash('Your custom build request has been submitted successfully! We will contact you shortly.', 'success')
            return redirect(url_for('custom_build_request_thanks')) # Redirect to a new 'thank you' page
        else:
            # save_custom_requests already flashed an error
            app.logger.error(f"Failed to save custom build request ID: {request_id}")
            # Re-render form if saving failed
            return render_template('custom.html',
                                   name=name, email=email, budget=budget,
                                   primary_use=primary_use, cpu_pref=cpu_pref,
                                   gpu_pref=gpu_pref, ram_amount=ram_amount,
                                   details=details, os_pref=os_pref)

    # --- Handle GET Request ---
    # Just show the blank form
    return render_template('custom.html')

# --- ADDED: Route for custom build thank you page ---
@app.route('/custom/thanks')
def custom_build_request_thanks():
     # Consider creating templates/custom_thanks.html for better styling
     return """
     <!DOCTYPE html>
     <html>
     <head><title>Request Received</title></head>
     <body>
         <h1>Thank You!</h1>
         <p>Your custom build request has been received. We'll review your requirements and get back to you soon via email.</p>
         <p><a href="/">Return Home</a></p>
     </body>
     </html>
     """

# --- Support Route ---
@app.route('/support', methods=['GET', 'POST'])
def support_ticket():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        issue = request.form.get('issue', '').strip()
        errors = []
        if not name: errors.append("Name is required.")
        if not email: errors.append("Email is required.") # Add better validation if needed
        if not issue: errors.append("Issue description is required.")
        if errors:
            for error in errors: flash(error, "warning")
            return render_template("support.html", name=name, email=email, issue=issue)

        # Use ISO format for timestamp
        timestamp = datetime.datetime.now().isoformat()
        ticket_id = str(uuid.uuid4())
        ticket = {
            "id": ticket_id,
            "name": name,
            "email": email,
            "issue": issue,
            "timestamp": timestamp, # Use ISO format
            "status": "open"
        }
        tickets = load_tickets()
        tickets.append(ticket)
        if save_tickets(tickets):
            app.logger.info(f"New support ticket: ID {ticket_id} by {name}")
            subject = f"New Support Ticket #{ticket_id[:8]} from {name}"
            # Format body, maybe use formatted timestamp
            try:
                formatted_time = format_datetime(datetime.datetime.fromisoformat(timestamp)) if BABEL_INSTALLED else timestamp
            except:
                formatted_time = timestamp # Fallback
            body = f"New ticket submitted:\n\nName: {name}\nEmail: {email}\nIssue:\n{issue}\n\nTime: {formatted_time}"
            admin_email = app.config.get('EMAIL_ADDRESS')
            if admin_email: send_email(admin_email, subject, body)
            flash(f"Support ticket submitted successfully. Your ticket ID is {ticket_id}.", "success")
            return redirect(url_for('support_ticket'))
        else:
            # Error flashed by save_tickets
            return render_template("support.html", name=name, email=email, issue=issue) # Re-render form
    # GET request
    return render_template("support.html")


# --- Checkout Routes ---
@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    item_name = request.form.get('item')
    amount_str = request.form.get('amount')
    customer_email = request.form.get('email') # Get email from hidden input
    item_id = request.form.get('item_id') # Get item ID

    if not item_name or not amount_str or not item_id:
        flash("Missing item details.", "danger")
        return redirect(request.referrer or url_for('prebuilts'))
    try:
        amount = float(amount_str)
        if amount <= 0: raise ValueError("Amount must be positive.")
        amount_cents = int(round(amount * 100))
    except ValueError:
        flash("Invalid amount specified.", "danger")
        return redirect(request.referrer or url_for('prebuilts'))

    if not customer_email: # Basic email check
        flash("Email is required for purchase.", "danger")
        # Consider adding a way for user to input email if not provided
        return redirect(request.referrer or url_for('prebuilts'))

    order_id = str(uuid.uuid4())
    timestamp = datetime.datetime.now().isoformat() # Use ISO format

    # Store details in session to retrieve after payment
    session['pending_order_details'] = {
        "item_id": item_id, # Store item ID too
        "item_name": item_name,
        "amount": amount,
        "order_id": order_id,
        "email": customer_email,
        "timestamp": timestamp
    }
    app.logger.info(f"Creating Stripe session for pending Order ID: {order_id}, Item: {item_name}, Email: {customer_email}")

    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': item_name,
                        # Optionally add description, images here if desired
                        # 'description': f"Prebuilt PC: {item_name}",
                        # 'images': [url_for('static', filename=f'images/{item_id}.jpg', _external=True)] # Example image URL
                    },
                    'unit_amount': amount_cents,
                },
                'quantity': 1,
            }],
            mode='payment',
            # Include session_id in success URL for verification
            success_url=url_for('thank_you', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=url_for('prebuilts', _external=True), # Redirect back to products on cancel
            customer_email=customer_email, # Pre-fill email
            # Store order details in metadata for webhook processing (recommended) or thank you page verification
            metadata={
                'order_id': order_id,
                'customer_email': customer_email,
                'item_id': item_id,
                'item_name': item_name
            }
        )
        return redirect(checkout_session.url, code=303)
    except stripe.error.StripeError as e:
        err_msg = e.user_message or str(e)
        app.logger.error(f"Stripe API error creating session for Order ID {order_id}: {err_msg}", exc_info=True)
        flash(f"Payment processing error: {err_msg}. Please try again or contact support.", "danger")
        session.pop('pending_order_details', None) # Clear pending order
        return redirect(request.referrer or url_for('prebuilts'))
    except Exception as e:
        app.logger.error(f"Unexpected error creating checkout session for Order ID {order_id}: {e}", exc_info=True)
        flash("Could not initiate checkout. Please try again.", "danger")
        session.pop('pending_order_details', None) # Clear pending order
        return redirect(request.referrer or url_for('prebuilts'))


@app.route('/thankyou')
def thank_you():
    stripe_session_id = request.args.get('session_id')
    if not stripe_session_id:
        flash("Invalid request. No session ID provided.", "warning")
        return redirect(url_for('index'))

    app.logger.info(f"Thank you page accessed for Stripe session: {stripe_session_id}")

    try:
        checkout_session = stripe.checkout.Session.retrieve(stripe_session_id)
        payment_status = checkout_session.payment_status
        # Get order details reliably from Stripe metadata
        order_id_from_stripe = checkout_session.metadata.get('order_id')
        customer_email_from_stripe = checkout_session.metadata.get('customer_email') or checkout_session.customer_details.email
        item_name_from_stripe = checkout_session.metadata.get('item_name', "Unknown Item")
        item_id_from_stripe = checkout_session.metadata.get('item_id')
        amount_paid = checkout_session.amount_total / 100.0 # Amount in dollars
        timestamp_from_stripe = datetime.datetime.fromtimestamp(checkout_session.created).isoformat()

        app.logger.info(f"Stripe session {stripe_session_id} status: {payment_status}, Order ID: {order_id_from_stripe}, Email: {customer_email_from_stripe}")

        if payment_status != "paid":
            flash("Payment was not successful or is still processing.", "warning")
            return redirect(url_for('index'))

        # Use data retrieved directly from Stripe for reliability
        order_data = {
            "item_id": item_id_from_stripe,
            "item_name": item_name_from_stripe,
            "amount": amount_paid,
            "order_id": order_id_from_stripe or f"stripe_{stripe_session_id}", # Fallback ID
            "email": customer_email_from_stripe,
            "timestamp": timestamp_from_stripe,
            "stripe_session_id": stripe_session_id,
            "payment_status": payment_status # Record status
        }

        # Check if order already saved (e.g., via webhook or previous visit)
        orders = load_orders()
        if not any(o.get('stripe_session_id') == stripe_session_id for o in orders):
            orders.append(order_data)
            if save_orders(orders):
                app.logger.info(f"Saved confirmed Order ID: {order_data['order_id']}")
                # Clear pending session data only AFTER successfully saving
                session.pop('pending_order_details', None)
            else:
                app.logger.error(f"CRITICAL: Failed to save confirmed Order ID: {order_data['order_id']} from Stripe session {stripe_session_id}")
                # Don't clear session data if save failed, maybe flash warning
                flash("Payment successful, but failed to record order internally. Please contact support.", "danger")
        else:
            app.logger.warning(f"Order {order_data['order_id']} (Stripe: {stripe_session_id}) was already saved. Displaying thank you page again.")
            session.pop('pending_order_details', None) # Clear session data even if duplicate

        # --- Generate PDF Receipt ---
        pdf_filename = f"receipt_{order_data['order_id']}.pdf"
        pdf_filepath = os.path.join(RECEIPT_DIR, pdf_filename)
        try:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", 'B', 16)
            pdf.cell(0, 10, txt="John's Easy Tech - Purchase Receipt", ln=True, align='C')
            pdf.ln(10)
            pdf.set_font("Arial", size=12)
            pdf.cell(40, 10, txt="Order ID:")
            pdf.cell(0, 10, txt=order_data['order_id'], ln=True)
            pdf.cell(40, 10, txt="Item:")
            pdf.cell(0, 10, txt=order_data['item_name'], ln=True) # Use item_name
            pdf.cell(40, 10, txt="Amount Paid:")
            pdf.cell(0, 10, txt=f"${order_data['amount']:.2f} USD", ln=True)
            pdf.cell(40, 10, txt="Date:")
             # Format date nicely if possible
            try:
                formatted_time = format_datetime(datetime.datetime.fromisoformat(order_data['timestamp'])) if BABEL_INSTALLED else order_data['timestamp']
            except: formatted_time = order_data['timestamp']
            pdf.cell(0, 10, txt=formatted_time, ln=True)
            pdf.cell(40, 10, txt="Paid By:")
            pdf.cell(0, 10, txt=order_data['email'], ln=True)
            pdf.ln(10)
            pdf.set_font("Arial", 'I', 10)
            terms_url = url_for('terms', _external=True)
            pdf.multi_cell(0, 5, txt=f"Thank you for your purchase! By completing this order, you agreed to the Terms and Conditions available at: {terms_url}")
            pdf.output(pdf_filepath, "F")
            app.logger.info(f"Generated PDF receipt: {pdf_filepath}")
            # Store path in session for download button
            session['last_receipt_path'] = pdf_filepath
            session['last_receipt_filename'] = pdf_filename
        except Exception as pdf_err:
            app.logger.error(f"Failed PDF receipt generation for Order ID {order_data['order_id']}: {pdf_err}", exc_info=True)
            session.pop('last_receipt_path', None)
            session.pop('last_receipt_filename', None)
            flash("Payment successful, but there was an error generating your receipt. Please contact support if needed.", "warning")

        # --- Send Email Confirmation (Optional Attachment) ---
        email_subject = f"Your John's Easy Tech Order Receipt - #{order_data['order_id'][:8]}"
        email_body = f"Thank you for your order!\n\nOrder ID: {order_data['order_id']}\nItem: {order_data['item_name']}\nAmount Paid: ${order_data['amount']:.2f}\nDate: {formatted_time}\n\nYou can view our terms at: {url_for('terms', _external=True)}\n\nIf you need support, please visit: {url_for('support_ticket', _external=True)}"

        # Decide whether to attach PDF - might require Flask-Mail or more complex smtplib setup
        # For now, sending plain text:
        send_email(order_data['email'], email_subject, email_body)
        # If using Flask-Mail, you could attach like this:
        # with app.open_resource(pdf_filepath) as fp:
        #     msg.attach(pdf_filename, "application/pdf", fp.read())
        # mail.send(msg)

        # Render thank you page, passing order data
        return render_template('thankyou.html', order=order_data)

    except stripe.error.StripeError as e:
        err_msg = e.user_message or str(e)
        app.logger.error(f"Stripe verification error for session {stripe_session_id}: {err_msg}", exc_info=True)
        flash(f"Could not verify payment: {err_msg}. If payment was taken, please contact support.", "danger")
        return redirect(url_for('index'))
    except Exception as e:
        app.logger.error(f"Unexpected error on thank you page for session {stripe_session_id}: {e}", exc_info=True)
        flash("An unexpected error occurred after payment processing. Please contact support.", "danger")
        return redirect(url_for('index'))


@app.route('/download-receipt')
def download_receipt():
    pdf_filepath = session.get('last_receipt_path')
    pdf_filename = session.get('last_receipt_filename', 'receipt.pdf') # Default filename

    if pdf_filepath and os.path.exists(pdf_filepath):
        try:
            app.logger.info(f"Serving receipt download: {pdf_filepath} as {pdf_filename}")
            return send_file(pdf_filepath, as_attachment=True, download_name=pdf_filename)
        except Exception as e:
            app.logger.error(f"Error sending receipt file {pdf_filepath}: {e}", exc_info=True)
            flash("Could not download the receipt file.", "danger")
            return redirect(request.referrer or url_for('index')) # Redirect back
    else:
        app.logger.warning(f"Receipt download failed: Path='{pdf_filepath}' File Exists: {os.path.exists(pdf_filepath) if pdf_filepath else 'N/A'}")
        flash("Receipt not found or your session may have expired.", "warning")
        return redirect(url_for('index'))


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

# --- Route to display the edit form ---
@app.route('/admin/edit_product/<product_id>', methods=['GET'])
@admin_required
def admin_edit_product_form(product_id):
    """Displays the form to edit an existing product."""
    prebuilts = load_prebuilts()
    product_to_edit = next((p for p in prebuilts if p.get('id') == product_id), None)

    if not product_to_edit:
        flash("Product not found.", "danger")
        return redirect(url_for('admin_view_products'))

    # Get categories for the dropdown suggestions
    categories = sorted(list(set(pc.get('category', 'General Use') for pc in prebuilts)))

    return render_template('admin/edit_product.html', product=product_to_edit, categories=categories)

# --- Route to handle the update submission ---
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

    try:
        # Get current product data to use as defaults if form fields are missing
        product_data = prebuilts[product_index]

        # Get updated data from form, falling back to original data if needed
        name = request.form.get('name', product_data.get('name', '')).strip()
        description = request.form.get('description', product_data.get('description', '')).strip()
        price_str = request.form.get('price', str(product_data.get('price', '0'))).strip()
        image = request.form.get('image', product_data.get('image', '')).strip()
        category = request.form.get('category', product_data.get('category', 'General Use')).strip()

        # --- Basic Manual Validation (Replace/Enhance with WTForms) ---
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
                price = updated_price # Only update if valid and non-negative
        except ValueError:
            errors.append("Invalid price format. Please enter a number.")

        if errors:
            for error in errors:
                flash(error, "warning")
            # Re-render the edit form with current (potentially invalid) submitted data
            # Construct dict with submitted values to refill form correctly
            failed_product_data = product_data.copy() # Start with original data
            failed_product_data.update({ # Overwrite with submitted values
                 'name': name, 'description': description,
                 'price': price_str, # Keep price as string for form repopulation
                 'image': image, 'category': category
            })
            categories = sorted(list(set(pc.get('category', 'General Use') for pc in prebuilts)))
            return render_template('admin/edit_product.html', product=failed_product_data, categories=categories)
        # --- End Validation ---

        # Update product details in the list
        prebuilts[product_index]['name'] = name
        prebuilts[product_index]['description'] = description
        prebuilts[product_index]['price'] = price # Store the validated float price
        prebuilts[product_index]['image'] = image or DEFAULT_IMAGE # Use default if image cleared
        prebuilts[product_index]['category'] = category

        # Save the updated list back to JSON
        if save_prebuilts(prebuilts):
            flash(f"Product '{name}' updated successfully.", "success")
            app.logger.info(f"Admin updated product ID: {product_id} (Name: {name})")
        # else: error message flashed by save_prebuilts

        return redirect(url_for('admin_view_products'))

    except Exception as e:
        app.logger.error(f"Update product {product_id} failed unexpectedly: {e}", exc_info=True)
        flash("An unexpected error occurred when updating the product.", "danger")
        return redirect(url_for('admin_view_products'))


@app.route('/admin/logout')
@admin_required
def admin_logout():
    username = session.get('admin_username', app.config.get("ADMIN_USERNAME", "admin")) # Get username if stored
    session.pop('admin_logged_in', None)
    session.clear() # Clear entire session for security
    flash('You have been logged out.', 'success')
    app.logger.info(f"Admin logout: {username}")
    return redirect(url_for('admin_login'))

# --- Admin Dashboard & Content Management ---
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    try:
        products = load_prebuilts()
        tickets = load_tickets()
        orders = load_orders()
        # Calculate open tickets count safely
        open_ticket_count = sum(1 for t in tickets if isinstance(t, dict) and t.get('status') == 'open')
    except Exception as e:
        app.logger.error(f"Failed to load data for admin dashboard: {e}", exc_info=True)
        flash("Error loading dashboard data.", "danger")
        products, tickets, orders, open_ticket_count = [], [], [], 0
    # Pass last 10 orders, reversed (newest first)
    return render_template("admin/dashboard.html", products=products, tickets=tickets, orders=orders[-10:][::-1], open_ticket_count=open_ticket_count)

@app.route('/admin/products', methods=['GET'])
@admin_required
def admin_view_products():
    prebuilts = load_prebuilts()
    categories = sorted(list(set(pc.get('category', 'General Use') for pc in prebuilts)))
    # Group PCs by category
    categorized_pcs = {cat: [pc for pc in prebuilts if pc.get('category', 'General Use') == cat] for cat in categories}
    return render_template('admin/products.html', categorized_pcs=categorized_pcs, categories=categories)

@app.route('/admin/add_product', methods=['POST'])
@admin_required
def admin_add_product():
    # TODO: Add CSRF check if using Flask-WTF
    try:
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        price_str = request.form.get('price', '0').strip()
        image = request.form.get('image', '').strip()
        category = request.form.get('category', 'General Use').strip()

        # --- Basic Manual Validation (Replace/Enhance with WTForms) ---
        errors = []
        if not name: errors.append("Product name is required.")
        if not description: errors.append("Product description is required.")
        if not category: errors.append("Product category is required.")
        price = 0.0
        try:
            price = float(price_str)
            if price < 0:
                 errors.append("Price cannot be negative.")
        except ValueError:
            errors.append("Invalid price format. Please enter a number.")

        if errors:
            for error in errors: flash(error, "warning")
            # Redirect back to product page, consider passing failed data if needed
            return redirect(url_for('admin_view_products'))
        # --- End Validation ---

        new_product_id = str(uuid.uuid4())
        new_product = {
            "id": new_product_id,
            "name": name,
            "description": description,
            "price": price,
            "image": image or DEFAULT_IMAGE, # Use default if blank
            "category": category
        }
        prebuilts = load_prebuilts()
        prebuilts.append(new_product)
        if save_prebuilts(prebuilts):
            flash(f"Product '{name}' added successfully.", "success")
            app.logger.info(f"Admin added product ID: {new_product_id} (Name: {name})")
        # else: Error flashed by save_prebuilts

        return redirect(url_for('admin_view_products'))

    except Exception as e:
        app.logger.error(f"Add product failed unexpectedly: {e}", exc_info=True)
        flash("An unexpected error occurred while adding the product.", "danger")
        return redirect(url_for('admin_view_products'))


@app.route('/admin/delete_product/<product_id>', methods=['POST'])
@admin_required
def admin_delete_product(product_id):
    # TODO: Add CSRF check if using Flask-WTF
    try:
        prebuilts = load_prebuilts()
        initial_len = len(prebuilts)
        product_to_delete = next((p for p in prebuilts if p.get('id') == product_id), None)

        if not product_to_delete:
             flash("Product not found.", "warning")
             app.logger.warning(f"Delete failed: Product ID {product_id} not found.")
             return redirect(url_for('admin_view_products'))

        # Filter out the product
        prebuilts_filtered = [p for p in prebuilts if p.get('id') != product_id]

        # Save the filtered list
        if save_prebuilts(prebuilts_filtered):
            deleted_name = product_to_delete.get('name', f'ID {product_id[:8]}')
            flash(f"Product '{deleted_name}' deleted successfully.", "success")
            app.logger.info(f"Admin deleted product ID: {product_id} (Name: {deleted_name})")
        # else: Error flashed by save_prebuilts

        return redirect(url_for('admin_view_products'))

    except Exception as e:
        app.logger.error(f"Error deleting product {product_id}: {e}", exc_info=True)
        flash("An unexpected error occurred while deleting the product.", "danger")
        return redirect(url_for('admin_view_products'))

@app.route('/admin/tickets', methods=['GET'])
@admin_required
def admin_view_tickets():
    tickets = load_tickets()
    # Get filter/search params
    ticket_status_filter = request.args.get("status", "all").lower()
    search_query = request.args.get("search", "").strip().lower()

    # Apply filtering
    filtered_tickets = tickets
    if ticket_status_filter == "open":
        filtered_tickets = [t for t in filtered_tickets if isinstance(t, dict) and t.get('status') == 'open']
    elif ticket_status_filter == "closed":
        filtered_tickets = [t for t in filtered_tickets if isinstance(t, dict) and t.get('status') == 'closed']

    # Apply search
    if search_query:
         filtered_tickets = [
            t for t in filtered_tickets if isinstance(t, dict) and (
                search_query in t.get("name", "").lower() or
                search_query in t.get("email", "").lower() or
                search_query in t.get("issue", "").lower() or
                search_query in t.get("id", "").lower() # Search by full or partial ID
            )
         ]
    # Sort tickets by timestamp (newest first) - assumes ISO format
    try:
        filtered_tickets.sort(key=lambda t: t.get('timestamp', ''), reverse=True)
    except Exception as sort_err:
        app.logger.warning(f"Could not sort tickets by timestamp: {sort_err}")

    return render_template('admin/tickets.html', tickets=filtered_tickets, ticket_status_filter=ticket_status_filter, search_query=search_query)

@app.route('/admin/close_ticket/<ticket_id>', methods=['POST'])
@admin_required
def admin_close_ticket(ticket_id):
    # TODO: Add CSRF check if using Flask-WTF
    try:
        tickets = load_tickets()
        ticket_found = False
        ticket_updated = False
        for ticket in tickets:
            if isinstance(ticket, dict) and ticket.get("id") == ticket_id:
                ticket_found = True
                if ticket.get("status") != "closed":
                    ticket["status"] = "closed"
                    # Optional: Add a closed_timestamp
                    # ticket["closed_timestamp"] = datetime.datetime.now().isoformat()
                    if save_tickets(tickets):
                        flash(f"Ticket {ticket_id[:8]} marked as closed.", "success")
                        app.logger.info(f"Admin closed ticket ID: {ticket_id}")
                        ticket_updated = True
                    # else: Error flashed by save_tickets
                else:
                    flash(f"Ticket {ticket_id[:8]} was already closed.", "info")
                    ticket_updated = True # Still considered 'found and handled'
                break # Found the ticket, no need to continue loop

        if not ticket_found:
            flash("Ticket not found.", "warning")
            app.logger.warning(f"Close ticket failed: Ticket ID {ticket_id} not found.")

        # Redirect back with filters preserved
        status_filter = request.form.get('status_filter', 'all')
        search_query = request.form.get('search_query', '')
        return redirect(url_for('admin_view_tickets', status=status_filter, search=search_query))

    except Exception as e:
        app.logger.error(f"Error closing ticket {ticket_id}: {e}", exc_info=True)
        flash("An unexpected error occurred while closing the ticket.", "danger")
        return redirect(url_for('admin_view_tickets'))


@app.route('/admin/test-email', methods=['POST'])
@admin_required
def admin_test_email():
    # TODO: Add CSRF check if using Flask-WTF
    admin_email = app.config.get('EMAIL_ADDRESS')
    if not admin_email:
        flash("Admin email address is not configured in settings.", "danger")
        return redirect(url_for('admin_dashboard'))

    subject = f"Test Email from {app.config.get('YOUR_DOMAIN', 'Your Website')} Admin Panel"
    # Use ISO format for timestamp in email body
    timestamp = datetime.datetime.now().isoformat()
    try:
        formatted_time = format_datetime(datetime.datetime.fromisoformat(timestamp)) if BABEL_INSTALLED else timestamp
    except: formatted_time = timestamp # Fallback
    body = f"This is a test email sent from the admin panel.\n\nTime: {formatted_time}"

    if send_email(admin_email, subject, body):
        flash(f'Test email sent successfully to {admin_email}. Please check your inbox (and spam folder).', 'success')
        app.logger.info(f"Admin triggered test email to {admin_email}")
    else:
        # Error message flashed by send_email helper
        app.logger.error(f"Admin test email failed to send to {admin_email}")

    return redirect(url_for('admin_dashboard')) # Redirect back to dashboard


# --- Security Check Routes ---
def check_security_status():
    """Performs basic security checks and returns status dict."""
    app.logger.info("Running security checks...")
    status = {
        'timestamp': datetime.datetime.now().isoformat(),
        'checks_performed': []
    }
    checks = status['checks_performed']

    # 1. Debug Mode Check
    is_debug = app.config['DEBUG']
    checks.append({
        'name': 'Debug Mode Status',
        'status': 'WARNING' if is_debug else 'OK',
        'details': f"Debug mode is currently {'ON' if is_debug else 'OFF'}. " + ("This reveals detailed errors and should be OFF in a live production environment." if is_debug else "Correct setting for production.")
    })

    # 2. Admin Password Hash Check
    has_hash = bool(app.config.get('ADMIN_PASSWORD_HASH'))
    checks.append({
        'name': 'Admin Password Configuration',
        'status': 'OK' if has_hash else 'CRITICAL',
        'details': "Checks if the ADMIN_PASSWORD environment variable is set. " + ("It is set (should contain a secure HASH, not plaintext)." if has_hash else "CRITICAL: Env var MUST be set to a securely generated password HASH.")
    })

    # 3. Secret Key Check
    secret_key = app.config.get('SECRET_KEY')
    is_weak_key = not secret_key or secret_key in ['temporary-insecure-key-for-dev-only', 'a_default_secret_key_for_development'] # Check against default/weak keys
    checks.append({
        'name': 'Application Secret Key',
        'status': 'CRITICAL' if is_weak_key else 'OK',
        'details': "Checks if SECRET_KEY is set and is not a known weak/default value. " + ("CRITICAL: A strong, unique secret key is required for session security." if is_weak_key else "Secret key appears to be set.")
    })

    # 4. Email Configuration Check
    email_ok = bool(app.config.get('EMAIL_ADDRESS') and app.config.get('EMAIL_PASSWORD'))
    checks.append({
        'name': 'Email Sending Configuration',
        'status': 'OK' if email_ok else 'WARNING',
        'details': "Checks if EMAIL_ADDRESS and EMAIL_PASSWORD environment variables are set. " + ("Both appear set." if email_ok else "WARNING: One or both variables missing; email sending will fail.")
    })

    # 5. Stripe Keys Check (Warn if using test keys in production env)
    is_prod_env = app.config['FLASK_ENV'] == 'production'
    secret_key_exists = bool(app.config.get('STRIPE_SECRET_KEY'))
    public_key_exists = bool(app.config.get('STRIPE_PUBLIC_KEY'))
    using_test_secret = app.config.get('STRIPE_SECRET_KEY','').startswith('sk_test_')
    using_test_public = app.config.get('STRIPE_PUBLIC_KEY','').startswith('pk_test_')
    stripe_status = 'OK'
    stripe_details = "Checks if Stripe keys are set and appropriate for the environment."

    if not secret_key_exists or not public_key_exists:
        stripe_status = 'WARNING'
        stripe_details += f" WARNING: {'Secret' if not secret_key_exists else ''}{' and ' if not secret_key_exists and not public_key_exists else ''}{'Public' if not public_key_exists else ''} Stripe key(s) missing! Payments will fail."
    elif is_prod_env and (using_test_secret or using_test_public):
        stripe_status = 'WARNING'
        stripe_details += f" WARNING: Using TEST {'Secret' if using_test_secret else ''}{' and ' if using_test_secret and using_test_public else ''}{'Public' if using_test_public else ''} key(s) in PRODUCTION environment! Real payments will not be processed."
    elif not is_prod_env and not using_test_secret and secret_key_exists:
        stripe_status = 'INFO' # Using Live keys in dev might be intentional but good to note
        stripe_details += " INFO: Using LIVE Stripe secret key in non-production environment."
    # Add more checks if needed (e.g., check webhook secret)

    checks.append({ 'name': 'Stripe API Keys', 'status': stripe_status, 'details': stripe_details })

    # 6. Data Directory Writable Check (Basic)
    try:
        test_file = os.path.join(DATA_DIR, '.writable_test')
        with open(test_file, 'w') as f: f.write('test')
        os.remove(test_file)
        writable_status = 'OK'
        writable_details = f"Data directory ({DATA_DIR}) appears writable."
    except Exception as e:
        writable_status = 'CRITICAL'
        writable_details = f"CRITICAL: Cannot write to data directory ({DATA_DIR}). Sessions, data files, receipts, logs will fail. Error: {e}"
        app.logger.error(writable_details, exc_info=True)

    checks.append({'name': 'Data Directory Writable', 'status': writable_status, 'details': writable_details })


    # Calculate Overall Status
    if any(c['status'] == 'CRITICAL' for c in checks): status['overall_status'] = 'CRITICAL'
    elif any(c['status'] == 'WARNING' for c in checks): status['overall_status'] = 'WARNING'
    else: status['overall_status'] = 'OK'

    # Save status to file
    if not save_json_data(SECURITY_STATUS_FILE, status):
        app.logger.error("Failed to save security status to file!")
        # Maybe flash an error here too?
    return status

def get_last_security_status():
    """Loads the last saved security status from JSON file."""
    app.logger.info(f"Fetching last security status from {SECURITY_STATUS_FILE}")
    status_data = load_json_data(SECURITY_STATUS_FILE, default_data=None)
    if status_data is None:
        # load_json_data failed (error already logged/flashed) or file doesn't exist yet
        return {'message': 'Security status file not found or unreadable. Run check first.', 'timestamp': None, 'checks_performed': []}
    elif not isinstance(status_data, dict) or 'timestamp' not in status_data:
        app.logger.warning(f"Invalid format in security status file: {SECURITY_STATUS_FILE}")
        # Attempt recovery or return error state
        return {'message': 'Security status file is invalid. Run check again.', 'timestamp': None, 'checks_performed': []}
    # Ensure keys exist for template rendering
    status_data.setdefault('overall_status', 'UNKNOWN')
    status_data.setdefault('checks_performed', [])
    return status_data


@app.route('/admin/security-check', methods=['POST'])
@admin_required
def run_security_check():
    """Runs security checks and redirects to status page."""
    # TODO: Add CSRF check if using Flask-WTF
    try:
        status = check_security_status() # This now saves the status too
        if status.get('overall_status') == 'CRITICAL':
            flash("CRITICAL security issues found! Please review the status details.", "danger")
        elif status.get('overall_status') == 'WARNING':
            flash("Security check completed with WARNINGS. Please review the status details.", "warning")
        else:
            flash("Security check completed. All checks passed (OK or INFO).", "success")
        app.logger.info(f"Admin triggered security check. Overall: {status.get('overall_status')}")
    except Exception as e:
        app.logger.error(f"Security check run failed: {e}", exc_info=True)
        flash("An error occurred while running security checks.", "danger")
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
        app.logger.error(f"Failed to display security status page: {e}", exc_info=True)
        flash("Error retrieving security status.", "danger")
        return redirect(url_for('admin_dashboard'))


# --- Error Handlers ---
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
    # Redirect to admin login if trying to access admin area, otherwise index
    if request.path.startswith('/admin'):
         return redirect(url_for('admin_login', next=request.url))
    else:
         return redirect(url_for('index'))

@app.errorhandler(500)
def internal_error(error):
    # Note: error variable might not contain detailed info unless debug is on
    app.logger.error(f'Internal Server Error on path {request.path}', exc_info=True) # Log detailed traceback
    message = "An unexpected internal error occurred. We have been notified and are looking into it."
    # Avoid showing detailed errors in production
    # if app.debug: message = f"Internal Server Error: {error}"
    return render_template('error.html', error_code=500, error_message=message), 500

# Generic exception handler (catches errors not handled by specific handlers)
@app.errorhandler(Exception)
def handle_exception(e):
    # Log the detailed exception
    app.logger.error(f'Unhandled Exception on path {request.path}', exc_info=e)
    # Generic message for the user
    message = "An unexpected error occurred. Please try again later or contact support if the issue persists."
    # Avoid showing specific exception details in production
    # if app.debug: message = f"Unhandled Exception: {e}"
    return render_template('error.html', error_code=500, error_message=message), 500

# --- Main Execution ---
# This block is mainly for local development using `python app.py`.
# OnRender/Gunicorn/Waitress will typically import the `app` object directly.
if __name__ == '__main__':
    # Port is often set by the hosting environment (e.g., PORT env var)
    port = int(os.environ.get("PORT", 5000))
    # Debug mode is controlled by FLASK_DEBUG env var or app.config['DEBUG']
    # Host '0.0.0.0' makes the server accessible externally (needed for Docker/OnRender)
    # Host '127.0.0.1' (default) is only accessible locally
    host = '0.0.0.0' if os.environ.get("FLASK_ENV") == 'production' else '127.0.0.1'
    # Use debug=app.config['DEBUG'] to respect the config setting
    app.run(host=host, port=port, debug=app.config['DEBUG'])