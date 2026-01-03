import os
import sys
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, url_for
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from werkzeug.security import check_password_hash, generate_password_hash

from utils.database import select_one

SQLITE_PREFIX = 'sqlite:///' if sys.platform.startswith(
    'win') else 'sqlite:////'


class Base(DeclarativeBase):
    """
    The model base class for `SQLAlchemy`.
    """
    pass


# Initialize app
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET')
app.config['SQLALCHEMY_DATABASE_URI'] = SQLITE_PREFIX + str(
    Path(app.root_path) / 'data.db')

# Initialize database
db = SQLAlchemy(app, model_class=Base)

# Initialize Flask-Login
login_manager = LoginManager(app)


class User(db.Model, UserMixin):
    """
    The table to store user information.
    """
    __tablename__ = 'user'
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(128))
    username: Mapped[str] = mapped_column(String(64))
    admin_level: Mapped[int] = mapped_column(Integer)
    password_hash: Mapped[str | None] = mapped_column(String(128))

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return self.password_hash is None or check_password_hash(
            self.password_hash, password)


@login_manager.user_loader
def load_user(user_id: str):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    # Check if we're logging in
    if request.method == 'GET':
        return render_template('login.html')

    # Unpack
    email = request.form.get('email')
    password = request.form.get('password')

    # Invalid input
    if not email or not password:
        flash('Invalid input.', 'error')
        return redirect(url_for('login_page'))

    # Fetch user data
    user = select_one(db, User, email=email)

    # Validate password
    if user is not None and user.check_password(password):
        if not login_user(user):
            flash('Error.', 'error')
            return redirect(url_for('login_page'))
        flash('Success.', 'success')
        return redirect(url_for('index_page'))

    flash('Invalid email or password.', 'error')
    return redirect(url_for('login_page'))


@app.route('/signup', methods=['GET', 'POST'])
def signup_page():
    # Check if we're signing up
    if request.method == 'GET':
        return render_template('signup.html')

    # Unpack
    email = request.form.get('email')
    username = request.form.get('username')
    password = request.form.get('password')
    password2 = request.form.get('password2')

    # Basic validation
    if not email or not username or not password or not password2:
        flash('Please fill out all fields.', 'error')
        return redirect(url_for('signup_page'))

    if password != password2:
        flash('Passwords do not match.', 'error')
        return redirect(url_for('signup_page'))

    # Check uniqueness
    exists_email = select_one(db, User, email=email)
    if exists_email:
        flash('An account with that email already exists.', 'error')
        return redirect(url_for('signup_page'))

    exists_username = select_one(db, User, username=username)
    if exists_username:
        flash('That username is already taken.', 'error')
        return redirect(url_for('signup_page'))

    # Create user
    try:
        user = User(
            email=email,  # type: ignore
            username=username,  # type: ignore
            admin_level=0)  # type: ignore
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.exception('Failed to create user')
        flash('Unable to create account.', 'error')
        return redirect(url_for('signup_page'))

    flash('Account created.', 'success')
    return redirect(url_for('login_page'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Goodbye.')
    return redirect(url_for('index_page'))


@app.route('/')
def index_page():
    return render_template("index.html")


@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404
