from flask_login import UserMixin  # mixin for managing user authentication states
from sqlalchemy.sql import func  # Utility for database functions
from . import db  # Import the database object from the __init__.py file


# Define the Note model to represent user-created notes
class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(500))
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    # Foreign key to associate the note with a specific user
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


# Define the User model to represent application users
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    # Relationship to associate users with their notes
    # This creates a one-to-many relationship where one user can have multiple notes
    notes = db.relationship('Note')
