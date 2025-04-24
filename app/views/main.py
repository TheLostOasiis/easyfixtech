from flask import Blueprint, render_template
from app import limiter

bp = Blueprint('main', __name__)

@bp.route('/')
@limiter.limit("60 per minute")
def index():
    return render_template('home.html')
