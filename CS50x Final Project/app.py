import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from help import apology, login_required

# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///project.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    # User reached route via "POST"
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("Must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("Must provide password", 400)

        # Ensure password confirmation was submitted
        elif not request.form.get("confirmation"):
            return apology("Must confirm password", 400)

        # Ensure password and confirmation match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Passwords do not match", 400)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure name doesn't already exist
        if len(rows) != 0:
            return apology("Username already exists", 400)

        # Insert new user to the database
        db.execute(
            "INSERT INTO users (username, hash) VALUES(?, ?)",
            request.form.get("username"),
            generate_password_hash(request.form.get("password")),
        )

        # Query database for the new inserted user
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Remember which user logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to the homepage
        return redirect("/")

    # User reached route via "GET"
    else:
        return render_template("register.html")


@app.route("/")
@login_required
def index():
    """Show Welcome Page"""

    return render_template("index.html")


@app.route("/keyschart")
@login_required
def keyschart():
    """Show Keys Chart"""

    return render_template("keyschart.html")


@app.route("/chordschart")
@login_required
def chordschart():
    """Show Chords Chart"""

    return render_template("chordschart.html")


@app.route("/cpgenerator", methods=["GET", "POST"])
@login_required
def cpgenerator():
    """Generator Mechanism"""
    if request.method == "POST":
        keyname = request.form["keyname"]

        if not keyname:
            return apology("Must provide key")

        progressions = db.execute(
            "SELECT * FROM progressions WHERE keyname LIKE ?", keyname
        )

        return render_template("results.html", progressions=progressions)

    else:
        return render_template("cpgenerator.html")


@app.route("/results")
@login_required
def results():
    """Show results"""

    return render_template("results.html")


@app.route("/createprogression", methods=["GET", "POST"])
@login_required
def createprogression():
    """User Can Create Custom Progressions"""
    if request.method == "POST":
        userID = session["user_id"]
        userDB = db.execute("SELECT username FROM users WHERE id = ?", userID)
        user = userDB[0]["username"]
        keyname = request.form["keyname"]
        progression = request.form["progression"]
        chords = request.form["chords"]

        if not keyname or not progression or not chords:
            return apology("Must Provide Data in All Fields")

        db.execute(
            "INSERT INTO `create` (id, keyname, progression, chords) VALUES (?, ?, ?, ?)",
            userID,
            keyname,
            progression,
            chords,
        )

        progressions = db.execute(
            "SELECT keyname, progression, chords FROM `create` WHERE id =?", userID
        )

        return render_template("profile.html", user=user, progressions=progressions)

    else:
        return render_template("createprogression.html")


@app.route("/profile")
@login_required
def profile():
    """Show User's Progression"""
    userID = session["user_id"]
    progressions = db.execute(
        "SELECT keyname, progression, chords FROM `create` WHERE id = ?", userID
    )

    return render_template("profile.html", progressions=progressions)
