# app/routes.py

from .blueprints.auth import auth_bp
from .blueprints.dashboard import dashboard_bp
from .blueprints.goals import goals_bp
from .blueprints.scans import scans_bp
from .blueprints.terminal import terminal_bp
from .blueprints.api import api_bp

def register_blueprints(app):
    app.register_blueprint(auth_bp, url_prefix='/')
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
    app.register_blueprint(goals_bp, url_prefix='/goals')
    app.register_blueprint(scans_bp, url_prefix='/scans')
    app.register_blueprint(terminal_bp, url_prefix='/terminal')
    app.register_blueprint(api_bp, url_prefix='/api')
