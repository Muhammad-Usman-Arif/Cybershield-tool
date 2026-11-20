from flask import Blueprint, render_template
from flask_login import login_required

help_bp = Blueprint('help_bp', __name__)


@help_bp.route('/')
@login_required
def index():
    """SOC Analyst Knowledge Base & Security Guidance Center."""
    return render_template('help/index.html', title='Knowledge Base & SOC Playbook')
