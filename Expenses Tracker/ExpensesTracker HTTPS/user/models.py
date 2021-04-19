from flask import Flask, jsonify, request, session, redirect
from passlib.hash import pbkdf2_sha256
from bson.objectid import ObjectId
import pymongo
import uuid
from datetime import datetime

client = pymongo.MongoClient('localhost', 27017)
db = client.user_login_system


class User:

    def start_session(self, user):
        del user['password']
        session['logged_in'] = True
        session['user'] = user
        return jsonify(user), 200

    def signup(self):
        print(request.form)

        # Create the user object
        user = {
            "_id": uuid.uuid4().hex,
            "name": request.form.get('name'),
            "email": request.form.get('email'),
            "password": request.form.get('password'),
            "user_type": request.form.get('user_type')
        }

        # Encrypt the password
        user['password'] = pbkdf2_sha256.encrypt(user['password'])

        # Check for existing email address
        if db.users.find_one({"email": user['email']}):
            return jsonify({"error": "Email address already in use"}), 400

        if db.users.insert_one(user):
            return self.start_session(user)

        return jsonify({"error": "Signup failed"}), 400

    def signout(self):
        session.clear()
        return redirect('/')

    def login(self):

        user = db.users.find_one({
            "email": request.form.get('email')
        })

        if user and pbkdf2_sha256.verify(request.form.get('password'), user['password']):
            return self.start_session(user)

        return jsonify({"error": "Invalid login credentials"}), 401

    def create(self, name, email, password,user_type="user"):
        if not db.users.find_one({"email": email}):
            user = {
                "_id": uuid.uuid4().hex,
                "name": name,
                "email": email,
                "password": pbkdf2_sha256.encrypt(password),
                "user_type": user_type
            }
            db.users.insert_one(user)

    def update(self, ID, name, email, password):

        self.ID = ID
        self.name = name
        self.email = email
        self.password = password

        user = db.users.find_one({"_id": self.ID})

        if not name:
            name = user["name"]
        if not email:
            email = user["email"]
        if not password:
            password = user["password"]
        if password:
            password = pbkdf2_sha256.encrypt(password)

        db.users.update_one(
            {"_id": self.ID},
            {"$set": {
                "name": name,
                "email": email,
                "password": password,
            }
            })

    def delete(self, ID):
        self.ID = ID

        db.users.delete_one({"_id": self.ID})


class Expenses:
    def delete(self, email, ID):
        self.email = email
        self.ID = ID
        expense = db.expenses.find_one({"_id": ObjectId(self.ID)})
        if expense["email"] == self.email or self.email=="admin":
            db.expenses.delete_one(expense)

    def update(self, ID, amount, description, comment, email):

        self.ID = ID
        self.amount = amount
        self.description = description
        self.comment = comment
        self.email = email
        expense = db.expenses.find_one({"_id": ObjectId(self.ID)})

        if self.email == expense["email"] or self.email=="admin":
            if not amount:
                amount = expense["Amount"]
            if not description:
                description = expense["Description"]
            if not comment:
                comment = expense["Comment"]

            db.expenses.update_one(
                {"_id": ObjectId(request.form["_id"])},
                {"$set": {
                    "Amount": amount,
                    "Description": description,
                    "Comment": comment,
                    "Date": datetime.now(),
                }
                })

    def create(self, amount, description, comment, email):
        self.amount = amount
        self.description = description
        self.comment = comment
        self.email = email

        db.expenses.insert_one({
            "Amount": self.amount,
            "Description": self.description,
            "Comment": self.comment,
            "Date": datetime.now(),
            "email": self.email
        })
