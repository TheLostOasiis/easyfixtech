from flask import Flask, render_template, request, redirect, send_file
import stripe
import os
import smtplib
import json
from dotenv import load_dotenv
from datetime import datetime
from fpdf import FPDF
import uuid

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Stripe keys from .env
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
YOUR_DOMAIN = 'https://johnseasytech.com'

# Email credentials
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

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
