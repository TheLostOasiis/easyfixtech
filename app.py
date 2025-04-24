from flask import Flask, render_template, request, redirect
import stripe
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Stripe keys from .env
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
YOUR_DOMAIN = 'http://localhost:5000'  # Update after deploying

@app.route('/')
def index():
    return render_template('index.html')

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

if __name__ == '__main__':
    app.run(debug=True)
