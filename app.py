from flask import Flask, render_template, request, redirect
import stripe
import os
import smtplib
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Stripe keys from .env
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
YOUR_DOMAIN = 'https://easyfixtech.onrender.com'

# Email credentials
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# Load PreBuilt PCs from JSON file with fallback image
DEFAULT_IMAGE = 'static/images/default.jpg'

def load_prebuilts():
    with open('prebuilts.json', 'r') as f:
        prebuilts = json.load(f)
    for pc in prebuilts:
        if 'image' not in pc or not pc['image']:
            pc['image'] = DEFAULT_IMAGE
    return prebuilts

@app.route('/')
def index():
    prebuilts = load_prebuilts()
    return render_template('index.html', prebuilts=prebuilts)

@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': request.form['item'],
                    },
                    'unit_amount': int(float(request.form['amount']) * 100),
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
    return render_template('thankyou.html')

@app.route('/support', methods=['POST'])
def support_ticket():
    name = request.form.get('name')
    email = request.form.get('email')
    issue = request.form.get('issue')

    subject = f"New Support Ticket from {name}"
    body = f"Name: {name}\nEmail: {email}\nIssue: {issue}"
    message = f"Subject: {subject}\n\n{body}"

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.sendmail(EMAIL_ADDRESS, EMAIL_ADDRESS, message)
    except Exception as e:
        return f"Email failed: {str(e)}"

    return "Support ticket received! We'll get back to you soon."

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
