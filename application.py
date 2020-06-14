import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session,url_for
from flask_session import Session

from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from datetime import datetime
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # ask for all user shares (answer is list of dictionaries)
    all_shares = db.execute("SELECT symbol, SUM(shares) as 'shares' FROM transactions WHERE user_id = :user_id GROUP BY symbol HAVING SUM(shares) > 0",
    user_id=session['user_id'])

    print(all_shares)
    money = 0

    # add name of company and last price of share
    for row in all_shares:  # for all user's shares (add info to dicts)
        #request for share information
        req = lookup(row['symbol'])
        #count all user money, include shares
        money += req['price'] * row['shares']
        #add new info to all_shares
        row.update({"name":req['name'], "price": usd(req['price']), "total": usd(row['shares'] * req['price'])})

    #ask user's cash(return list of dictionar)
    cash =db.execute("SELECT cash FROM users WHERE id = :id", id = session['user_id'])

    #calculate total money (shares + cash)
    money += cash[0]['cash']

    return render_template("index.html", data = all_shares, cash = usd(cash[0]['cash']), money = usd(money))


@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    '''Deposit money'''
    if request.method == "GET":
        return render_template("deposit.html")
    elif request.method == "POST":
        deposit = float(request.form.get("deposit"))
        if not deposit:
           return apology("missing deposite")
        else:
            if db.execute("UPDATE users SET cash = cash + :deposit WHERE id = :user_id", deposit = deposit, user_id = session['user_id']):
                flash("Money deposited")
                return redirect("/")
            else:
                return apology("can't make an operation")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    elif request.method == "POST":
        if not request.form.get("symbol"):
            return apology("Missing symbol")

        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not shares:
            return apology("missing shares")

        try:
            shares = int(shares)
        except ValueError:
            return apology("shares must be a positive integer")


        if not isinstance(shares,int) or shares < 0:
            return apology("shares must be a positive integer")

        response = lookup(symbol)
        if not response:
            return apology("invalid symbol")
        req = (db.execute("SELECT cash FROM users WHERE id = :id", id = session["user_id"]))
        cash = req[0]["cash"]

        t_price = response['price'] * float(shares)
        if t_price > cash:
            return apology("can't afford")
        else:
            db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES(:user_id, :symbol, :shares, :price)",
                       user_id = session["user_id"], symbol =  response['symbol'], shares = shares, price = response['price'])

            db.execute("UPDATE users SET cash = :new WHERE id = :user_id", new = cash - t_price, user_id = session["user_id"])

            flash("Bought!")
            return redirect("/")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    username = request.args.get('username')

    if username and not db.execute("SELECT username FROM users WHERE username = :username", username = username):
        return jsonify(True)
    else:
        return jsonify(False)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_transactions = db.execute("SELECT * FROM transactions WHERE user_id = :user_id", user_id = session['user_id'])

    return render_template("history.html", transactions = user_transactions)


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    elif request.method == "POST":
        if not request.form.get("symbol"):
            return apology("Missing symbol")
        result = lookup(request.form.get("symbol"))
        if not result:
            return apology("Invalid symbol")

        return render_template("quoted.html", name = result["name"], symbol = result["symbol"], price = usd(result["price"]))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username:
            return apology("Missing Username")


        if not password:
            return apology("Missing password")
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("Passwords don't match")

        hash_pass = generate_password_hash(password)


        check = db.execute("SELECT username FROM users WHERE username = :username", username = username)
        if check:
            return apology("This username is not available")

        new_user = db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash_pass)", username = username, hash_pass = hash_pass)


        session["user_id"] = new_user
        flash("Registered!")
        return redirect("/")
    elif request.method == "GET":
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        user_shares = db.execute("SELECT symbol, sum(shares) as Shares FROM transactions \
        WHERE user_id = :user_id GROUP BY symbol HAVING sum(shares) > 0", user_id = session['user_id'])
        return render_template("sell.html", data = user_shares)
    elif request.method == "POST":
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        if not symbol:
            return apology("Missing symbol")
        symbol_shares = db.execute("SELECT sum(shares) as Shares FROM transactions WHERE symbol = :symbol AND user_id = :user_id",
        symbol = symbol, user_id = session['user_id'])

        if shares > symbol_shares[0]['Shares']:
            return apology("too many shares")
        else:
            response = lookup(symbol)
            #update user cash, add money from transaction
            if not db.execute("UPDATE users SET cash = cash + :new WHERE id = :user_id ", new = shares * response['price'], user_id = session['user_id']):
                return apology("can't make transaction")
            else:
                db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES(:user_id, :symbol, :shares, :price)",
                           user_id = session["user_id"], symbol = symbol, shares = -shares, price = response['price'])
        flash("Sold!")
        return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
