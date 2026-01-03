import os
import sys
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, url_for
from flask_login import LoginManager, UserMixin, login_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, String, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from werkzeug.security import check_password_hash, generate_password_hash

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
    password_hash: Mapped[str] = mapped_column(String(128))

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


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
    user = db.session.execute(select(User).filter_by(email=email)).scalar()

    # Validate password
    if user is not None and user.check_password(password):
        if not login_user(user):
            flash('Error.', 'error')
            return redirect(url_for('login_page'))
        flash('Success.', 'success')
        return redirect(url_for('index_page'))

    flash('Invalid email or password.', 'error')
    return redirect(url_for('login_page'))


@app.route('/')
def index_page():
    return render_template("index.html")


@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404
