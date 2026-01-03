from flask import Flask, render_template

app = Flask(__name__)


@app.route('/login')
def login_page():
    # For now render the login form. Authentication handling not implemented here.
    return render_template("login.html")


@app.route('/')
def index_page():
    return render_template("index.html")


@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404
