# __init__.py
from flask import Flask
from flask_pymongo import PyMongo
from flask_login import LoginManager
from flask_bcrypt import Bcrypt

mongo = PyMongo()
login_manager = LoginManager()
bcrypt = Bcrypt()

def create_app():
    app = Flask(__name__)
    app.config["MONGO_URI"] = "mongodb://localhost:27017/mydatabase"
    app.config["SECRET_KEY"] = "supersecretkey"
    
    # Initialize extensions
    mongo.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    bcrypt.init_app(app)
    
    # Register blueprints
    from .blueprints.auth import auth_bp
    from .blueprints.dashboard import dashboard_bp
    from .blueprints.goals import goals_bp
    from .blueprints.scans import scans_bp
    from .blueprints.terminal import terminal_bp
    from .blueprints.api import api_bp
    from .blueprints.vuln import vuln_bp
    from .blueprints.gobuster import gobuster_bp  # <- EKLEDİK
    
    app.register_blueprint(auth_bp, url_prefix='/')
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
    app.register_blueprint(goals_bp, url_prefix='/goals')
    app.register_blueprint(scans_bp, url_prefix='/scans')
    app.register_blueprint(terminal_bp, url_prefix='/terminal')
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(vuln_bp, url_prefix='/vuln')
    app.register_blueprint(gobuster_bp, url_prefix='/gobuster')  # <- EKLEDİK
    
    return app