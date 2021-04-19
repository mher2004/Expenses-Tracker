from bson import ObjectId
from flask import Flask, render_template, session, redirect, request
from functools import wraps
import pymongo
from user.models import Expenses, User

app = Flask(__name__)
app.secret_key = b'\xcc^\x91\xea\x17-\xd0W\x03\xa7\xf8J0\xac8\xc5'

# Database
client = pymongo.MongoClient('localhost', 27017)
db = client.user_login_system


# Decorators
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            return redirect('/')

    return wrap


# Routes
from user import routes


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/dashboard/', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == "POST":

        if session["user"]["user_type"] == "user":

            if request.form.get("update"):
                amount = request.form["amount"]
                description = request.form["description"]
                comment = request.form["comment"]
                ID = request.form["_id"]
                expense = Expenses()
                expense.update(ID, amount, description, comment, session["user"]["email"])

            elif request.form.get("delete"):
                expense = Expenses()
                expense.delete(session["user"]["email"], request.form["_id"])

            elif request.form.get("create"):
                amount = request.form["amount"]
                description = request.form["description"]
                comment = request.form["comment"]
                expense = Expenses()
                expense.create(amount, description, comment, session["user"]["email"])

        if session["user"]["user_type"] == "manager":

            if request.form.get("update"):
                name = request.form["name"]
                email = request.form["email"]
                password = request.form["password"]
                ID = request.form["_id"]
                user = User()
                user.update(ID, name, email, password)

            elif request.form.get("delete"):
                user = User()
                user.delete(request.form["_id"])

            elif request.form.get("create"):
                print(request.form)
                name = request.form["name"]
                email = request.form["email"]
                password = request.form["password"]
                user = User()
                user.create(name, email, password)

        if session["user"]["user_type"] == "admin":

            if request.form.get("update_user"):
                name = request.form["name"]
                email = request.form["email"]
                password = request.form["password"]
                ID = request.form["_id"]
                user = User()
                user.update(ID, name, email, password)

            elif request.form.get("delete_user"):
                user = User()
                user.delete(request.form["_id"])

            elif request.form.get("create_user"):
                print(request.form)
                name = request.form["name"]
                email = request.form["email"]
                password = request.form["password"]
                user_type = request.form["user_type"]
                user = User()
                user.create(name, email, password, user_type)

            elif request.form.get("update_exp"):
                amount = request.form["amount"]
                description = request.form["description"]
                comment = request.form["comment"]
                ID = request.form["_id"]
                expense = Expenses()
                expense.update(ID, amount, description, comment, "admin")

            elif request.form.get("delete_exp"):
                expense = Expenses()
                expense.delete("admin", request.form["_id"])

            elif request.form.get("create_exp"):
                amount = request.form["amount"]
                description = request.form["description"]
                comment = request.form["comment"]
                email = request.form["email"]
                expense = Expenses()
                expense.create(amount, description, comment, email)
    expenses = db.expenses.find({"email": session["user"]["email"]})
    expenses_admin = db.expenses.find()
    users = db.users.find({"user_type": "user"})
    users_admin = db.users.find()
    return render_template('dashboard.html', expenses=expenses, users=users, expenses_admin=expenses_admin,
                           users_admin=users_admin)
