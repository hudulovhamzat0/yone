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

    mongo.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)

    from .routes import main
    app.register_blueprint(main)

    return app
