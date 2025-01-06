from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager

db = SQLAlchemy()
DB_NAME = "database.db"


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'hjshjhdjah kjshkjdhjs'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    db.init_app(app)

    # Import and register Blueprints for modular route management
    from .views import views  # Routes for general views
    from .auth import auth  # Routes for authentication

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    from .models import User, Note # noqa
    
    # Create all database tables if they don't already exist
    with app.app_context():
        db.create_all()

    # Set up Flask-Login for managing user sessions
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'  # Redirect unauth users to the login page
    login_manager.init_app(app)  # Bind the login manager to the Flask app

    # Define a callback to load the current user by their ID
    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    return app


def create_database(app):
    if not path.exists('notes_webapp/' + DB_NAME):
        db.create_all(app=app)
        print('Created Database!')
