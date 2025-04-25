# -*- coding: utf-8 -*-
import os
import json
import smtplib
import uuid
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from functools import wraps
from io import BytesIO # Needed for sending file data potentially

from flask import (
    Flask, render_template, request, redirect, send_file,
    session, url_for, flash, jsonify, Response # Added Response
)
# Consider using Flask-WTF for forms and CSRF protection
# from flask_wtf import FlaskForm
# from wtforms import StringField, PasswordField, SubmitField, FloatField, TextAreaField, SelectField
# from wtforms.validators import DataRequired, Email, Length, NumberRange

from flask_session import Session # Handles server-side sessions
from fpdf import FPDF
import stripe
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash # For password hashing (recommended)

# --- Configuration ---
load_dotenv()

# --- Constants ---
# Ensure DATA_DIR is persistent and writable by the Flask app user
DATA_DIR = os.getenv("DATA_DIR", "/data")
PREBUILT_FILE = os.path.join(DATA_DIR, "prebuilts.json")
TICKETS_FILE = os.path.join(DATA_DIR, "tickets.json")
ORDERS_FILE = os.path.join(DATA_DIR, "orders.json")
# Store receipts in a non-static, persistent directory
RECEIPT_DIR = os.path.join(DATA_DIR, "receipts")
# Store logs in a directory relative to the app or define an absolute path
LOG_DIR = os.getenv("LOG_DIR", "logs")
DEFAULT_IMAGE = 'static/images/default.jpg' # Path relative to static folder

# --- Flask App Initialization ---
app = Flask(__name__, template_folder="app/templates", static_folder="app/static")

# --- Configuration Settings ---
# CRITICAL: Set a strong, random secret key in your .env file
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
if not app.config["SECRET_KEY"] or app.config["SECRET_KEY"] == 'dev-key-change-in-production':
    print("CRITICAL WARNING: SECRET_KEY is not set or is set to the default development value in .env!")
    # Consider raising an error or exiting in production if not set securely
    if os.getenv("FLASK_ENV") == "production":
         raise ValueError("SECRET_KEY must be set to a strong value in production!")
    else:
        # Use a temporary insecure key for non-production only IF NEEDED, but .env is preferred
        app.config["SECRET_KEY"] = 'temporary-insecure-key-for-dev-only'


# Server-side Session configuration
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = os.path.join(DATA_DIR, "flask_session")
app.config["SESSION_PERMANENT"] = False # Session lasts until browser closes unless configured otherwise
# app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7) # Example: Make sessions last 7 days

# Stripe Configuration
app.config["STRIPE_SECRET_KEY"] = os.getenv("STRIPE_SECRET_KEY")
app.config["STRIPE_PUBLIC_KEY"] = os.getenv("STRIPE_PUBLIC_KEY") # Needed for frontend usually

# Application Behavior Configuration
# Use http://127.0.0.1:5000 or http://localhost:5000 for local testing if not using HTTPS
app.config["YOUR_DOMAIN"] = os.getenv("DOMAIN", 'http://127.0.0.1:5000')
app.config["DEBUG"] = os.getenv("FLASK_DEBUG", "False").lower() in ("true", "1", "t")

# Email Configuration
app.config["EMAIL_ADDRESS"] = os.getenv("EMAIL_ADDRESS")
app.config["EMAIL_PASSWORD"] = os.getenv("EMAIL_PASSWORD") # Consider OAuth2 or App Password

# Admin Credentials (RECOMMENDATION: Use password hashing)
app.config["ADMIN_USERNAME"] = os.getenv("ADMIN_USERNAME", "admin")
app.config["ADMIN_PASSWORD"] = os.getenv("ADMIN_PASSWORD") # Store the plain password OR hash here
# Example if storing hash: app.config["ADMIN_PASSWORD_HASH"] = os.getenv("ADMIN_PASSWORD_HASH")

if not app.config["ADMIN_PASSWORD"] or app.config["ADMIN_PASSWORD"] == 'change-this-password-immediately':
     print("CRITICAL WARNING: ADMIN_PASSWORD is not set or uses a default insecure value!")
     # Consider raising error in production

# --- Initialize Extensions ---
Session(app)
if app.config["STRIPE_SECRET_KEY"]:
    stripe.api_key = app.config["STRIPE_SECRET_KEY"]
else:
    print("WARNING: STRIPE_SECRET_KEY is not set in .env. Stripe integration will fail.")

# --- Logging Setup ---
def setup_logging(app_instance):
    """Set up logging for the application"""
    log_level = logging.DEBUG if app_instance.debug else logging.INFO
    logging.basicConfig(level=log_level) # Basic console logging

    # File logging (optional, but good for production)
    if not app_instance.debug or os.getenv("FORCE_FILE_LOGGING"):
        try:
            os.makedirs(LOG_DIR, exist_ok=True)
            log_file = os.path.join(LOG_DIR, 'app.log')
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=1024 * 1024 * 5, # 5 MB
                backupCount=5
            )
            formatter = logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
            )
            file_handler.setFormatter(formatter)
            file_handler.setLevel(logging.INFO) # Log INFO level and above to file
            app_instance.logger.addHandler(file_handler)
            # Remove default Flask handler to avoid duplicate messages if file handler is added
            # Note: Be careful if other handlers are added elsewhere
            # from flask.logging import default_handler
            # app_instance.logger.removeHandler(default_handler)
            app_instance.logger.info(f'File logging enabled at {log_file}')

        except Exception as e:
            app_instance.logger.error(f"Failed to set up file logging: {e}")

    app_instance.logger.setLevel(log_level)
    app_instance.logger.info('Application startup')
    app_instance.logger.info(f'Debug mode: {app_instance.debug}')
    app_instance.logger.info(f'Domain configured as: {app_instance.config["YOUR_DOMAIN"]}')

setup_logging(app)

# --- Data Handling Helpers (using JSON, consider DB migration) ---
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
                # Handle empty file case
                content = f.read()
                if not content:
                    return default_data
                return json.loads(content)
    except (IOError, json.JSONDecodeError, OSError) as e:
        app.logger.error(f"Error loading JSON data from {filepath}: {e}")
        # Depending on severity, you might want to raise the exception
        # or return default_data / handle appropriately
        flash(f"Error accessing data file {os.path.basename(filepath)}. Please contact support.", "danger")
        return default_data # Be careful returning default, might hide persistent issues

def save_json_data(filepath, data):
    """Saves data to a JSON file."""
    try:
        dirpath = os.path.dirname(filepath)
        if dirpath: # Ensure directory exists only if path includes one
            os.makedirs(dirpath, exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4)
        return True
    except (IOError, OSError) as e:
        app.logger.error(f"Error saving JSON data to {filepath}: {e}")
        flash(f"Error saving data file {os.path.basename(filepath)}. Please try again.", "danger")
        return False

# Specific Loaders/Savers
def load_prebuilts():
    """Loads prebuilt PCs, ensuring default image and category."""
    prebuilts = load_json_data(PREBUILT_FILE, default_data=[]) # Define default data structure if needed
    for pc in prebuilts:
        pc.setdefault('image', DEFAULT_IMAGE)
        pc.setdefault('category', 'General Use')
        pc.setdefault('id', str(uuid.uuid4())) # Ensure items have IDs
    return prebuilts

def save_prebuilts(prebuilts_list):
    """Saves the list of prebuilt PCs."""
    return save_json_data(PREBUILT_FILE, prebuilts_list)

def load_tickets():
    """Loads support tickets."""
    return load_json_data(TICKETS_FILE, [])

def save_tickets(tickets_list):
    """Saves the list of support tickets."""
    return save_json_data(TICKETS_FILE, tickets_list)

def load_orders():
    """Loads past orders."""
    return load_json_data(ORDERS_FILE, [])

def save_orders(orders_list):
    """Saves the list of orders."""
    return save_json_data(ORDERS_FILE, orders_list)

# --- Initialization Logic ---
def initialize_data_files():
    """Initializes data files and directories if they don't exist."""
    app.logger.info("Initializing data directories and files...")
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        os.makedirs(app.config["SESSION_FILE_DIR"], exist_ok=True)
        os.makedirs(RECEIPT_DIR, exist_ok=True)
        app.logger.info(f"Ensured directories exist: {DATA_DIR}, {app.config['SESSION_FILE_DIR']}, {RECEIPT_DIR}")

        # Default Prebuilt PCs (only if file is empty or doesn't exist)
        if not os.path.exists(PREBUILT_FILE) or os.path.getsize(PREBUILT_FILE) == 0:
            app.logger.info(f"Prebuilt file {PREBUILT_FILE} not found or empty. Creating defaults.")
            default_prebuilts = [
                {
                    "id": str(uuid.uuid4()),
                    "name": "Gamer Beast 5000",
                    "price": 1499.99,
                    "description": "A top-tier rig with RTX 4070 Super and Ryzen 7 7800X3D.",
                    "image": "static/images/default.jpg", # Keep path relative to static
                    "category": "Gaming"
                },
                {
                    "id": str(uuid.uuid4()),
                    "name": "Code Cruncher Pro",
                    "price": 899.99,
                    "description": "Perfect for developers, preloaded with Linux and 32GB RAM.",
                    "image": "static/images/default.jpg",
                    "category": "Programming"
                }
            ]
            save_prebuilts(default_prebuilts)

        # Ensure other files exist (load_json_data handles creation)
        load_tickets()
        load_orders()
        app.logger.info("Data file initialization complete.")

    except Exception as e:
        app.logger.error(f"Failed during data file initialization: {e}", exc_info=True)
        # Depending on the error, you might want to halt startup

initialize_data_files() # Call initialization after helpers are defined

# --- Decorators ---
def admin_required(f):
    """Decorator to ensure the user is logged in as admin."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session or not session['admin_logged_in']:
            flash("Admin access required. Please log in.", "warning")
            # Store the intended destination to redirect after login
            return redirect(url_for('admin_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# --- Email Helper ---
def send_email(to_address, subject, body, attachment_path=None, attachment_filename=None):
    """Sends an email using configured credentials. Basic implementation."""
    sender = app.config.get("EMAIL_ADDRESS")
    password = app.config.get("EMAIL_PASSWORD")

    if not sender or not password:
        app.logger.error("Email address or password not configured. Cannot send email.")
        return False

    # Basic email structure (plain text)
    # For HTML emails and robust attachments, use email.mime modules or Flask-Mail
    message = f"Subject: {subject}\nFrom: {sender}\nTo: {to_address}\n\n{body}"

    try:
        # Using Gmail SMTP example. Adjust host/port for other providers.
        # Consider using OAuth2 for Gmail for better security.
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(sender, password)
            # Note: Basic sendmail doesn't handle attachments well.
            # This part needs rework if attachments are critical.
            if attachment_path and os.path.exists(attachment_path):
                 app.logger.warning("Basic email helper does not support attachments. Sending text only.")
                 # Here you would construct a MIME message if supporting attachments
            smtp.sendmail(from_addr=sender, to_addrs=to_address, msg=message.encode('utf-8')) # Ensure encoding
        app.logger.info(f"Email sent successfully to {to_address} with subject: {subject}")
        return True
    except smtplib.SMTPAuthenticationError:
        app.logger.error(f"Email authentication failed for {sender}. Check credentials or account security settings (e.g., 'less secure apps' or use App Password/OAuth2).")
        flash("Failed to send email due to authentication error. Please check server logs.", "danger")
        return False
    except Exception as e:
        app.logger.error(f"Failed to send email to {to_address}: {e}", exc_info=True)
        flash(f"Failed to send email: {e}. Check server logs.", "danger")
        return False

# --- Routes ---

# --- Public Routes ---
@app.route('/')
def index():
    """Renders the home page."""
    return render_template('home.html')

@app.route('/terms')
def terms():
    """Renders the terms and conditions page."""
    return render_template('terms.html')

@app.route('/prebuilts')
def prebuilts():
    """Displays prebuilt PCs categorized."""
    pcs = load_prebuilts()
    # Dynamically get categories from loaded PCs
    categories = sorted(list(set(pc.get('category', 'General Use') for pc in pcs)))
    categorized_pcs = {cat: [] for cat in categories}
    for pc in pcs:
        categorized_pcs[pc.get('category', 'General Use')].append(pc)

    return render_template("prebuilts.html", categorized_pcs=categorized_pcs, categories=categories)

@app.route('/custom')
def custom():
    """Renders the custom build request page (placeholder)."""
    # Add logic for custom builds if needed (e.g., a form)
    return render_template('custom.html')

# --- Support Routes ---
@app.route('/support', methods=['GET', 'POST'])
def support_ticket():
    """Handles support ticket submission form."""
    # TODO: Implement Flask-WTF Form for validation and CSRF protection
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        issue = request.form.get('issue', '').strip()

        # Basic validation example (Replace with WTForms validation)
        errors = []
        if not name: errors.append("Name is required.")
        if not email: errors.append("Email is required.") # Add email format validation
        if not issue: errors.append("Issue description is required.")

        if errors:
            for error in errors:
                flash(error, "warning")
            # Return the form with entered values
            return render_template("support.html", name=name, email=email, issue=issue)

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ticket_id = str(uuid.uuid4())
        ticket = {
            "id": ticket_id,
            "name": name,
            "email": email, # Consider validating email format seriously
            "issue": issue, # Consider sanitizing this if displayed directly in admin HTML
            "timestamp": timestamp,
            "status": "open"
        }

        tickets = load_tickets()
        tickets.append(ticket)
        if save_tickets(tickets):
            app.logger.info(f"New support ticket created: ID {ticket_id} by {name} ({email})")
            # Notify Admin
            subject = f"New Support Ticket #{ticket_id[:8]} from {name}"
            body = f"A new support ticket has been submitted:\n\nName: {name}\nEmail: {email}\nIssue:\n{issue}\n\nTime: {timestamp}\nStatus: Open"
            send_email(app.config["EMAIL_ADDRESS"], subject, body) # Send to admin email

            # Redirect to a thank you page or back to support with success message
            # return render_template("support_thankyou.html", name=name, ticket_id=ticket_id)
            flash(f"Support ticket submitted successfully. Your ticket ID is {ticket_id}. We will contact you shortly.", "success")
            return redirect(url_for('support_ticket')) # Redirect after successful POST
        else:
            # Error handled by save_tickets flashing a message
            return render_template("support.html", name=name, email=email, issue=issue)


    # GET request
    return render_template("support.html")


# --- Payment / Checkout Routes ---
@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    """Creates a Stripe Checkout session."""
    # TODO: Add WTForms validation for inputs if possible, or enhance manual checks
    item_name = request.form.get('item')
    amount_str = request.form.get('amount')
    customer_email = request.form.get('email') # Ensure form sends this if needed, or get from logged in user

    # Validate inputs
    if not item_name or not amount_str:
        flash("Missing item name or amount for checkout.", "danger")
        return redirect(request.referrer or url_for('prebuilts')) # Redirect back

    try:
        amount = float(amount_str)
        if amount <= 0:
             raise ValueError("Amount must be positive.")
        amount_cents = int(round(amount * 100)) # Use round() to avoid float precision issues converting to cents
    except ValueError:
        flash("Invalid amount specified.", "danger")
        return redirect(request.referrer or url_for('prebuilts'))

    if not customer_email:
        # Try to get from session if user is logged in, otherwise prompt or fail
        # For now, we'll require it from the form or fail
        flash("Customer email is required for checkout.", "danger")
        # return redirect(request.referrer or url_for('prebuilts'))
        # OR try getting from session: customer_email = session.get('user_email')
        # If still no email, redirect to login or prompt
        return redirect(request.referrer or url_for('prebuilts'))


    order_id = str(uuid.uuid4())
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Store minimal necessary data in session temporarily before redirecting to Stripe
    # This data will be retrieved in the 'thank_you' route after successful payment
    session['pending_order_details'] = {
        "item": item_name,
        "amount": amount, # Store original float amount
        "order_id": order_id,
        "email": customer_email,
        "timestamp": timestamp
    }
    app.logger.info(f"Creating Stripe session for Order ID (pending): {order_id}")

    try:
        # Create Stripe Checkout Session
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': item_name,
                        # 'description': 'Optional description here',
                        # 'images': ['url_to_product_image.jpg'], # Optional image
                    },
                    'unit_amount': amount_cents,
                },
                'quantity': 1,
            }],
            mode='payment',
            # Pass Stripe session ID back to our thank you page
            success_url=url_for('thank_you', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=url_for('prebuilts', _external=True), # Or cart page
            customer_email=customer_email, # Pre-fill email at Stripe
            metadata={
                'order_id': order_id, # Pass our internal order ID to Stripe metadata
                'customer_email': customer_email # Can store additional info if needed
                }
        )
        # Redirect customer to Stripe Checkout
        return redirect(checkout_session.url, code=303)

    except stripe.error.StripeError as e:
        app.logger.error(f"Stripe API error creating session for pending order {order_id}: {e}")
        flash(f"Payment processing error: {e.body.get('message', 'Unknown Stripe Error')}. Please try again.", "danger")
        session.pop('pending_order_details', None) # Clear pending order from session
        return redirect(request.referrer or url_for('prebuilts'))
    except Exception as e:
        app.logger.error(f"Error creating Stripe checkout session for pending order {order_id}: {e}", exc_info=True)
        flash("An unexpected error occurred initiating checkout. Please try again.", "danger")
        session.pop('pending_order_details', None) # Clear pending order
        return redirect(request.referrer or url_for('prebuilts'))


@app.route('/thankyou')
def thank_you():
    """Page shown after successful payment."""
    stripe_session_id = request.args.get('session_id')
    if not stripe_session_id:
        flash("Invalid access to thank you page. No session ID provided.", "warning")
        return redirect(url_for('index'))

    app.logger.info(f"Thank you page accessed with Stripe session ID: {stripe_session_id}")

    try:
        # Retrieve the session from Stripe to verify payment status and details
        checkout_session = stripe.checkout.Session.retrieve(stripe_session_id)
        payment_status = checkout_session.payment_status
        order_id_from_stripe = checkout_session.metadata.get('order_id')

        app.logger.info(f"Retrieved Stripe session {stripe_session_id}. Status: {payment_status}. Order ID from metadata: {order_id_from_stripe}")

        # Check if payment was successful
        if payment_status != "paid":
             flash("Payment was not successful or is still processing.", "warning")
             app.logger.warning(f"Thank you page accessed for non-paid/pending Stripe session: {stripe_session_id}, Status: {payment_status}")
             # Potentially clear pending session data if it exists
             session.pop('pending_order_details', None)
             return redirect(url_for('index')) # Redirect if not paid

        # Retrieve details stored temporarily in Flask session BEFORE redirecting to Stripe
        order_data = session.pop('pending_order_details', None)

        # Verify the order ID from session matches Stripe metadata, if possible
        if not order_data:
            app.logger.warning(f"Flask session 'pending_order_details' missing for successful Stripe session {stripe_session_id}. Attempting recovery from Stripe data.")
            # Fallback: reconstruct necessary info from Stripe if session data is lost
            # This is less ideal as you might miss custom data stored only in Flask session
            order_data = {
                "item": checkout_session.line_items.data[0].description if checkout_session.line_items else "Purchased Item",
                "amount": checkout_session.amount_total / 100.0,
                "order_id": order_id_from_stripe or f"stripe_{stripe_session_id}", # Use Stripe order ID or generate fallback
                "email": checkout_session.customer_details.email,
                "timestamp": datetime.fromtimestamp(checkout_session.created).strftime('%Y-%m-%d %H:%M:%S'),
                "stripe_session_id": stripe_session_id # Store Stripe session ID for reference
            }
        elif order_data.get('order_id') != order_id_from_stripe:
             app.logger.warning(f"Order ID mismatch! Flask session had {order_data.get('order_id')}, Stripe metadata had {order_id_from_stripe} for session {stripe_session_id}. Using Stripe Order ID.")
             order_data['order_id'] = order_id_from_stripe # Trust Stripe metadata's order ID
             order_data['stripe_session_id'] = stripe_session_id

        else:
            # Session data exists and matches order ID, add stripe session ID for reference
             order_data['stripe_session_id'] = stripe_session_id
             app.logger.info(f"Successfully matched Flask session data for order {order_id_from_stripe}")


        # --- Save the confirmed order to persistent storage ---
        orders = load_orders()
        # Prevent duplicate order saving if user refreshes thank you page somehow
        if not any(o.get('stripe_session_id') == stripe_session_id for o in orders):
            orders.append(order_data)
            if save_orders(orders):
                 app.logger.info(f"Successfully saved confirmed Order ID: {order_data['order_id']} (Stripe Session: {stripe_session_id})")
            else:
                 app.logger.error(f"CRITICAL: Failed to save confirmed Order ID: {order_data['order_id']} after successful payment! (Stripe Session: {stripe_session_id})")
                 # Consider alternative notification/logging here
        else:
             app.logger.warning(f"Order {order_data['order_id']} (Stripe Session: {stripe_session_id}) already found in orders file. Skipping duplicate save.")

        # --- Generate Receipt PDF ---
        pdf_filename = f"receipt_{order_data['order_id']}.pdf"
        # Save PDF to the secure, non-static RECEIPT_DIR
        pdf_filepath = os.path.join(RECEIPT_DIR, pdf_filename)

        try:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", 'B', 16)
            pdf.cell(0, 10, txt="John's Easy Tech - Purchase Receipt", ln=True, align='C')
            pdf.ln(10)
            pdf.set_font("Arial", size=12)
            pdf.cell(40, 10, txt="Order #:", border=0)
            pdf.cell(0, 10, txt=order_data['order_id'], ln=True, border=0)
            pdf.cell(40, 10, txt="Item:", border=0)
            pdf.cell(0, 10, txt=order_data['item'], ln=True, border=0)
            pdf.cell(40, 10, txt="Amount Paid:", border=0)
            pdf.cell(0, 10, txt=f"${order_data['amount']:.2f} USD", ln=True, border=0)
            pdf.cell(40, 10, txt="Date:", border=0)
            pdf.cell(0, 10, txt=order_data['timestamp'], ln=True, border=0)
            pdf.cell(40, 10, txt="Paid By:", border=0)
            pdf.cell(0, 10, txt=order_data['email'], ln=True, border=0)
            pdf.ln(10)
            pdf.set_font("Arial", 'I', 10)
            terms_url = url_for('terms', _external=True)
            pdf.multi_cell(0, 5, txt=f"Thank you for your purchase! By completing this order, you agreed to the Terms and Conditions available at: {terms_url}")

            pdf.output(pdf_filepath, "F") # Save PDF to file
            app.logger.info(f"Generated PDF receipt: {pdf_filepath}")

            # Store receipt path in session for download link on thank you page
            session['last_receipt_path'] = pdf_filepath
            session['last_receipt_filename'] = pdf_filename

        except Exception as pdf_err:
             app.logger.error(f"Failed to generate PDF receipt for order {order_data['order_id']}: {pdf_err}", exc_info=True)
             # Don't store path in session if generation failed
             session.pop('last_receipt_path', None)
             session.pop('last_receipt_filename', None)
             flash("Your payment was successful, but there was an issue generating your PDF receipt. Please contact support.", "warning")


        # --- Send Email Confirmation (with or without PDF) ---
        email_subject = f"Your John's Easy Tech Order Receipt - #{order_data['order_id']}"
        email_body = f"Thank you for your order with John's Easy Tech!\n\n" \
                     f"Order #: {order_data['order_id']}\n" \
                     f"Item: {order_data['item']}\n" \
                     f"Amount Paid: ${order_data['amount']:.2f} USD\n" \
                     f"Date: {order_data['timestamp']}\n\n" \
                     f"You can view our terms and conditions here: {url_for('terms', _external=True)}\n\n" \
                     f"If you have any questions, please contact support."

        # Basic email helper doesn't support attachments. If implemented, pass pdf_filepath here.
        # send_email(order_data['email'], email_subject, email_body, attachment_path=pdf_filepath, attachment_filename=pdf_filename)
        send_email(order_data['email'], email_subject, email_body) # Sending without attachment for now

        # Render thank you page, passing order details for display
        return render_template('thankyou.html', order=order_data)

    except stripe.error.StripeError as e:
        app.logger.error(f"Stripe API error verifying session {stripe_session_id}: {e}", exc_info=True)
        flash(f"Error verifying payment status: {e.user_message or str(e)}. Please contact support if you believe payment was successful.", "danger")
        session.pop('pending_order_details', None) # Clear pending order
        return redirect(url_for('index'))
    except Exception as e:
        app.logger.error(f"Generic error in thank you processing for Stripe session {stripe_session_id}: {e}", exc_info=True)
        # Clean up potentially incomplete session data
        session.pop('pending_order_details', None)
        flash("An unexpected error occurred after payment. Please contact support.", "danger")
        return redirect(url_for('index'))


@app.route('/download-receipt')
def download_receipt():
    """Downloads the most recently generated receipt for the user's session."""
    pdf_filepath = session.get('last_receipt_path')
    pdf_filename = session.get('last_receipt_filename', 'receipt.pdf')

    if pdf_filepath and os.path.exists(pdf_filepath):
        try:
            app.logger.info(f"Serving receipt download: {pdf_filepath}")
            # Consider removing from session after download to prevent re-download?
            # session.pop('last_receipt_path', None)
            # session.pop('last_receipt_filename', None)
            return send_file(pdf_filepath, as_attachment=True, download_name=pdf_filename)
        except Exception as e:
            app.logger.error(f"Error sending receipt file {pdf_filepath}: {e}", exc_info=True)
            flash("Could not download receipt file.", "danger")
            return redirect(request.referrer or url_for('index'))
    else:
        app.logger.warning(f"Receipt download attempted but file not found or session invalid: Path='{pdf_filepath}'")
        flash("Receipt not found or session expired. Please contact support if needed.", "warning")
        return redirect(url_for('index'))


# --- Admin Routes ---
# Consider putting these in a separate Blueprint (e.g., admin_routes.py)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Handles admin login."""
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard')) # Already logged in

    # TODO: Implement Flask-WTF Form for validation and CSRF protection
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password') # Password from form

        # --- Password Verification ---
        # Option 1: Plain text comparison (Less Secure - Use only if password is not hashed)
        # stored_password = app.config.get("ADMIN_PASSWORD")
        # is_valid = (username == app.config.get("ADMIN_USERNAME") and stored_password and password == stored_password)

        # Option 2: Hashed password comparison (Recommended)
        stored_hash = app.config.get("ADMIN_PASSWORD") # Assuming ADMIN_PASSWORD in .env stores the HASH
        # Or use a dedicated config var like ADMIN_PASSWORD_HASH
        # stored_hash = app.config.get("ADMIN_PASSWORD_HASH")
        is_valid = False
        if username == app.config.get("ADMIN_USERNAME") and stored_hash and password:
            try:
                # Use check_password_hash if you stored a hash
                # is_valid = check_password_hash(stored_hash, password)

                # Fallback to plain text compare IF NOT using hashing (REMOVE THIS IF USING HASHING)
                if not stored_hash.startswith('pbkdf2:'): # Basic check if it looks like a hash
                     is_valid = (stored_hash == password)
                else:
                    # This branch means you intended to hash but didn't implement check_password_hash
                    app.logger.error("Password check failed: Stored password looks like a hash, but check_password_hash is commented out or not used.")

            except Exception as hash_error:
                app.logger.error(f"Error during password hash check: {hash_error}")
                is_valid = False # Fail safely

        # --- Handle Login Result ---
        if is_valid:
            session['admin_logged_in'] = True
            session.permanent = True # Optional: Make admin session last longer
            app.config['SESSION_PERMANENT'] = True # Required if PERMANENT_SESSION_LIFETIME is set
            app.logger.info(f"Admin login successful for user: {username}")
            next_url = request.args.get('next')
            # Basic security check: ensure next_url is internal to prevent open redirector
            if next_url and not next_url.startswith(('/', url_for('index'))):
                 app.logger.warning(f"Invalid 'next' URL detected during admin login: {next_url}. Redirecting to dashboard.")
                 next_url = url_for('admin_dashboard')
            return redirect(next_url or url_for('admin_dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
            app.logger.warning(f"Admin login failed for username attempt: {username}")

    # GET request or failed POST
    return render_template('admin/login.html')

@app.route('/admin/logout')
@admin_required # Ensure only logged-in admins can logout
def admin_logout():
    """Logs out the admin user."""
    username = session.get('admin_username', app.config.get("ADMIN_USERNAME", "admin")) # Get username for logging if stored
    session.pop('admin_logged_in', None)
    session.clear() # Clear the entire session for good measure
    flash('You have been logged out successfully.', 'success')
    app.logger.info(f"Admin logout successful for user: {username}")
    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Displays the main admin dashboard."""
    try:
        products = load_prebuilts()
        tickets = load_tickets()
        orders = load_orders() # Load orders for potential display

        # Simple ticket filtering example
        ticket_status_filter = request.args.get("status", "all").lower() # e.g., ?status=open
        if ticket_status_filter == "open":
             filtered_tickets = [t for t in tickets if t.get('status') == 'open']
        elif ticket_status_filter == "closed":
             filtered_tickets = [t for t in tickets if t.get('status') == 'closed']
        else:
             filtered_tickets = tickets # Show all

        open_ticket_count = sum(1 for t in tickets if t.get('status') == 'open')

        return render_template("admin/dashboard.html",
                               products=products,
                               tickets=filtered_tickets,
                               orders=orders[-10:],  # Show last 10 orders maybe
                               ticket_status_filter=ticket_status_filter,
                               open_ticket_count=open_ticket_count)

    except Exception as e:
        app.logger.error(f"Admin dashboard loading error: {e}", exc_info=True)
        flash("Error loading dashboard data. Some information may be missing.", "danger")
        # Render template with empty lists or minimal data to avoid complete failure
        return render_template("admin/dashboard.html", products=[], tickets=[], orders=[], error="Could not load dashboard data.")


@app.route('/admin/products', methods=['GET'])
@admin_required
def admin_view_products():
    """Displays page for managing products."""
    prebuilts = load_prebuilts()
    # Reuse categorization logic if needed for display
    categories = sorted(list(set(pc.get('category', 'General Use') for pc in prebuilts)))
    categorized_pcs = {cat: [] for cat in categories}
    for pc in prebuilts:
        categorized_pcs[pc.get('category', 'General Use')].append(pc)

    # TODO: Add a form instance here if using Flask-WTF for adding products
    # add_product_form = AddProductForm()
    return render_template('admin/products.html',
                           categorized_pcs=categorized_pcs,
                           categories=categories)
                           # add_product_form=add_product_form)


@app.route('/admin/add_product', methods=['POST'])
@admin_required
def admin_add_product():
    """Handles adding a new product via POST request."""
    # TODO: Integrate Flask-WTF Form validation here
    # form = AddProductForm()
    # if form.validate_on_submit():
    #    name = form.name.data ... etc.
    # else:
    #    flash('Form validation failed.', 'danger')
    #    # Need to re-render the products page with errors, tricky without dedicated add page/modal
    #    return redirect(url_for('admin_view_products')) # Simplified redirect

    # Manual validation (fallback if not using WTForms)
    try:
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        price_str = request.form.get('price', '0').strip()
        image = request.form.get('image', '').strip() # Consider image upload/handling later
        category = request.form.get('category', 'General Use').strip()

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
            for error in errors:
                flash(error, "warning")
            # Ideally, re-render the page with the form showing errors.
            # Simple redirect for now:
            return redirect(url_for('admin_view_products'))

        new_product = {
            "id": str(uuid.uuid4()), # Add a unique ID
            "name": name,
            "description": description, # Consider sanitizing if displayed raw
            "price": price,
            "image": image if image else DEFAULT_IMAGE, # Use default if empty path provided
            "category": category
        }

        prebuilts = load_prebuilts()
        prebuilts.append(new_product)
        if save_prebuilts(prebuilts):
            flash(f"Product '{name}' added successfully.", "success")
            app.logger.info(f"Admin added product: {name} (ID: {new_product['id']})")
        else:
            # Error message flashed by save_prebuilts
            pass
        return redirect(url_for('admin_view_products'))

    except Exception as e:
        app.logger.error(f"Add product failed unexpectedly: {e}", exc_info=True)
        flash("An unexpected error occurred when adding the product.", "danger")
        return redirect(url_for('admin_view_products'))


@app.route('/admin/delete_product/<product_id>', methods=['POST']) # Use POST for deletion
@admin_required
def admin_delete_product(product_id):
    """Handles deleting a product via POST request."""
    # TODO: Add CSRF token check here if using Flask-WTF manually or within a form
    try:
        prebuilts = load_prebuilts()
        initial_length = len(prebuilts)
        # Filter out the product with the matching ID
        prebuilts_filtered = [p for p in prebuilts if p.get('id') != product_id]

        if len(prebuilts_filtered) < initial_length:
            if save_prebuilts(prebuilts_filtered):
                product_name = next((p.get('name', 'Unknown') for p in prebuilts if p.get('id') == product_id), product_id)
                flash(f"Product '{product_name}' deleted successfully.", "success")
                app.logger.info(f"Admin deleted product ID: {product_id} (Name: {product_name})")
            else:
                 # Error flashed by save_prebuilts
                 pass
        else:
            flash("Product not found or already deleted.", "warning")
            app.logger.warning(f"Admin attempted to delete non-existent product ID: {product_id}")

        return redirect(url_for('admin_view_products'))
    except Exception as e:
        app.logger.error(f"Error deleting product {product_id}: {e}", exc_info=True)
        flash("An error occurred while deleting the product.", "danger")
        return redirect(url_for('admin_view_products'))


@app.route('/admin/tickets', methods=['GET'])
@admin_required
def admin_view_tickets():
     """Displays page for viewing and managing support tickets."""
     tickets = load_tickets()
     ticket_status_filter = request.args.get("status", "all").lower()
     search_query = request.args.get("search", "").strip().lower()

     filtered_tickets = tickets
     # Filter by status
     if ticket_status_filter == "open":
         filtered_tickets = [t for t in filtered_tickets if t.get('status') == 'open']
     elif ticket_status_filter == "closed":
         filtered_tickets = [t for t in filtered_tickets if t.get('status') == 'closed']

     # Filter by search query
     if search_query:
          filtered_tickets = [
              t for t in filtered_tickets if
              search_query in t.get("name", "").lower() or
              search_query in t.get("email", "").lower() or
              search_query in t.get("issue", "").lower() or
              search_query in t.get("id", "").lower()
          ]

     return render_template('admin/tickets.html',
                            tickets=filtered_tickets,
                            ticket_status_filter=ticket_status_filter,
                            search_query=search_query)


@app.route('/admin/close_ticket/<ticket_id>', methods=['POST']) # Use POST for status change
@admin_required
def admin_close_ticket(ticket_id):
    """Closes a specific support ticket."""
    # TODO: Add CSRF check
    try:
        tickets = load_tickets()
        ticket_found = False
        ticket_updated = False
        for ticket in tickets:
            if ticket.get("id") == ticket_id:
                ticket_found = True
                if ticket.get("status") != "closed":
                    ticket["status"] = "closed"
                    if save_tickets(tickets):
                        flash(f"Ticket {ticket_id[:8]} closed successfully.", "success")
                        app.logger.info(f"Admin closed ticket ID: {ticket_id}")
                        ticket_updated = True
                    else:
                        # Error flashed by save_tickets
                        pass
                else:
                    flash(f"Ticket {ticket_id[:8]} was already closed.", "info")
                    ticket_updated = True # No change needed, but treat as success for redirect
                break

        if not ticket_found:
            flash("Ticket not found.", "warning")
            app.logger.warning(f"Admin attempted to close non-existent ticket ID: {ticket_id}")

        # Redirect back to tickets page, preserving filters if possible
        status_filter = request.form.get('status_filter', 'all') # Get filter from hidden form field if needed
        search_query = request.form.get('search_query', '')
        return redirect(url_for('admin_view_tickets', status=status_filter, search=search_query))

    except Exception as e:
        app.logger.error(f"Error closing ticket {ticket_id}: {e}", exc_info=True)
        flash("An error occurred while closing the ticket.", "danger")
        return redirect(url_for('admin_view_tickets'))


@app.route('/admin/test-email', methods=['POST']) # Use POST for actions
@admin_required
def admin_test_email():
    """Sends a test email to the configured admin address."""
    # TODO: Add CSRF check
    admin_email = app.config.get('EMAIL_ADDRESS') # Send test TO the configured email
    if not admin_email:
         flash("Admin email address is not configured in .env file.", "danger")
         return redirect(url_for('admin_dashboard'))

    subject = "Test Email - John's Easy Tech Admin System"
    body = f"""
    This is a test email sent from the admin panel of your site: {app.config['YOUR_DOMAIN']}
    Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

    If you received this, your email sending configuration seems to be working for basic text emails.
    """
    if send_email(admin_email, subject, body):
        flash(f'Test email sent successfully to {admin_email}!', 'success')
        app.logger.info("Admin triggered test email successfully.")
    else:
        # Error message flashed by send_email helper
        app.logger.error("Admin triggered test email failed.")

    return redirect(url_for('admin_dashboard'))


# --- Security Check Routes (Placeholders - Implementation Needed) ---
# These need actual implementation based on your requirements.
def check_security_status():
    """Placeholder: Implement actual security checks."""
    app.logger.info("Running security checks (Placeholder)...")
    # Example checks:
    # - Check if .env exists and critical keys are set
    # - Check if DEBUG is False in production environment
    # - Check if default admin password is still used
    # - Check file permissions on data directories
    # - Check if using HTTPS (if request.is_secure)
    status = {
        'timestamp': datetime.now().isoformat(),
        'checks_performed': [
            {'name': 'Debug Mode', 'status': 'OK' if not app.config['DEBUG'] else 'WARNING', 'details': f"Debug mode is {'OFF' if not app.config['DEBUG'] else 'ON'}"},
            {'name': 'Admin Password', 'status': 'OK' if app.config.get('ADMIN_PASSWORD') != 'change-this-password-immediately' else 'CRITICAL', 'details': 'Default admin password check'},
            {'name': 'Secret Key Set', 'status': 'OK' if app.config.get('SECRET_KEY') != 'temporary-insecure-key-for-dev-only' else 'CRITICAL', 'details': 'Secret key configuration check'},
            # Add more checks here
        ],
        'overall_status': 'UNKNOWN' # Calculate based on check results
    }
    # Persist this status (e.g., save to a JSON file or database)
    # save_last_security_status(status)
    return status

def get_last_security_status():
    """Placeholder: Load the last saved security status."""
    app.logger.info("Fetching last security status (Placeholder)...")
    # Load status from where check_security_status saved it
    # return load_last_security_status()
    # Example default if no status saved yet:
    return {'message': 'Security status check has not been run yet or data is unavailable.', 'timestamp': None}


@app.route('/admin/security-check', methods=['POST'])
@admin_required
def run_security_check():
    """Runs security checks and flashes status (doesn't return JSON here)."""
    # TODO: Add CSRF check
    try:
        status = check_security_status()
        # Process status for flashing messages
        critical_issues = [c['name'] for c in status.get('checks_performed', []) if c['status'] == 'CRITICAL']
        warning_issues = [c['name'] for c in status.get('checks_performed', []) if c['status'] == 'WARNING']

        if critical_issues:
            flash(f"Security Check CRITICAL: Issues found in {', '.join(critical_issues)}", "danger")
        if warning_issues:
            flash(f"Security Check WARNING: Issues found in {', '.join(warning_issues)}", "warning")
        if not critical_issues and not warning_issues:
             flash("Security Check Completed: No major issues found.", "success")

        # Maybe save the status here if check_security_status doesn't do it
        app.logger.info(f"Admin ran security check. Result: {status}")
        return redirect(url_for('admin_dashboard')) # Redirect back after check
    except Exception as e:
        app.logger.error(f"Security check failed to run: {e}", exc_info=True)
        flash("Security check encountered an error during execution.", "danger")
        return redirect(url_for('admin_dashboard'))


@app.route('/admin/security-status')
@admin_required
def get_security_status_route():
    """Displays the last known security status (renders a template)."""
    try:
        status = get_last_security_status()
        return render_template('admin/security_status.html', status=status) # Needs this template
    except Exception as e:
        app.logger.error(f"Failed to get security status: {e}", exc_info=True)
        flash("Failed to retrieve security status information.", "danger")
        return redirect(url_for('admin_dashboard'))


# --- Error Handlers ---
@app.errorhandler(404)
def not_found_error(error):
    """Handles 404 Not Found errors."""
    app.logger.warning(f'Not Found: {request.path} (Referrer: {request.referrer}, IP: {request.remote_addr})')
    return render_template('error.html',
                           error_code=404,
                           error_message="Sorry, the page you are looking for doesn't exist."), 404

@app.errorhandler(403)
def forbidden_error(error):
    """Handles 403 Forbidden errors."""
    app.logger.warning(f'Forbidden access attempt: {request.path} by {request.remote_addr}')
    return render_template('error.html',
                           error_code=403,
                           error_message="Sorry, you don't have permission to access this page."), 403

@app.errorhandler(401)
def unauthorized_error(error):
    """Handles 401 Unauthorized errors (usually redirects to login)."""
    app.logger.warning(f'Unauthorized access attempt: {request.path} from {request.remote_addr}')
    flash("You need to be logged in to access this page.", "warning")
    # Redirect to admin login if trying to access admin area, otherwise maybe general login/index
    if request.path.startswith('/admin'):
        return redirect(url_for('admin_login', next=request.url))
    else:
        # Handle non-admin unauthorized access if applicable
        return redirect(url_for('index'))


@app.errorhandler(500)
def internal_error(error):
    """Handles 500 Internal Server errors."""
    # Log the full exception details for debugging
    app.logger.error(f'Internal Server Error on path {request.path}: {error}', exc_info=True)
    # Don't leak implementation details in production
    message = "An unexpected internal error occurred. We have been notified."
    if app.debug:
        message = f"Internal Server Error: {error}" # Show more detail in debug mode
    return render_template('error.html',
                           error_code=500,
                           error_message=message), 500

@app.errorhandler(Exception) # Generic catch-all for other exceptions
def handle_exception(e):
    """Handles uncaught exceptions."""
    # Log the specific exception that wasn't caught by other handlers
    app.logger.error(f'Unhandled Exception on path {request.path}: {e}', exc_info=True)
    # Return a generic 500 error page
    message = "An unexpected error occurred."
    if app.debug:
        message = f"Unhandled Exception: {e}"
    return render_template('error.html',
                           error_code=500,  # Treat as internal server error
                           error_message=message), 500


# --- Main Execution ---
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    # Debug mode is controlled by FLASK_DEBUG env var via app.config['DEBUG']
    # Host '0.0.0.0' makes it accessible on your network; use '127.0.0.1' for local access only.
    # IMPORTANT: Use a proper WSGI server (like Gunicorn or Waitress) in production, not app.run()!
    host = '0.0.0.0' if os.getenv("FLASK_ENV") == "production" else '127.0.0.1'
    app.run(host=host, port=port) # Debug determined by app.config['DEBUG']