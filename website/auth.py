from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User  # Import the User model from the models module
from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)  # For securely handling passwords
from . import db  # means from __init__.py import db
# Login management utilities
from flask_login import login_user, login_required, logout_user, current_user

# Define a Blueprint for the authentication routes
auth = Blueprint("auth", __name__)


# Login route: Handles GET and POST requests for user login
@auth.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Retrieve email and password from the login form
        email = request.form.get("email")
        password = request.form.get("password")

        # Check if a user exists with the given email
        user = User.query.filter_by(email=email).first()
        if user:
            # Verify the provided password matches the stored hash
            if check_password_hash(user.password, password):
                flash("Logged in successfully!", category="success")
                # Log the user in and remember the session
                login_user(user, remember=True)
                return redirect(url_for("views.home"))
            else:
                flash("Incorrect password!, Try again", category="error")

    return render_template("login.html", user=current_user)


# Logout route
@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


# Signup route: Handles GET and POST requests for user registration
@auth.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        # Retrieve data from the signup form
        email = request.form.get("email")
        first_name = request.form.get("first_name")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        # Check for various validation errors
        user = User.query.filter_by(email=email).first()
        if user:
            flash("Email already exists.", category="error")
        elif len(email) < 4:
            flash("Email must be longer than 4 characters.", category="error")
        elif len(first_name) < 2:
            flash("First name must be longer than 1 character.", category="error")
        elif password1 != password2:
            flash("Passwords don't match.", category="error")
        elif len(password1) < 8:
            flash("Passwords must be at least 8 characters.", category="error")
        else:
            # add user to database
            new_user = User(
                email=email,
                first_name=first_name,
                password=generate_password_hash(password1, method="pbkdf2:sha256"),
            )
            db.session.add(new_user)
            db.session.commit()
            flash("Account created!", category="success")
            return redirect(url_for("views.home"))

    return render_template("signup.html", user=current_user)
