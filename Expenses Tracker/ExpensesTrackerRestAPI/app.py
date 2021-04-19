from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'example'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///expensestracker.db'

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    manager = db.Column(db.Boolean)
    admin = db.Column(db.Boolean)


class Expenses(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Integer)
    date = db.Column(db.DateTime)
    description = db.Column(db.String(50))
    comment = db.Column(db.String(50))
    user_id = db.Column(db.Integer)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({"message": "Token is missing"}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], verify=False)
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({"message": "Token is invalid"}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route("/user", methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin and not current_user.manager:
        return jsonify({"message": "You don't have permission"})

    users = User.query.all()
    all_users = []
    for user in users:
        data = {}
        data["public_id"] = user.public_id
        data["name"] = user.name
        data["admin"] = user.admin
        data["manager"] = user.manager
        data["password"] = user.password
        all_users.append(data)

    return jsonify({"users": all_users})


@app.route("/user/<public_id>", methods=['GET'])
@token_required
def get_user(current_user, public_id):
    if not current_user.admin and not current_user.manager:
        return jsonify({"message": "You don't have permission"})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"message": "No user found!"})

    data = {}
    data["public_id"] = user.public_id
    data["name"] = user.name
    data["admin"] = user.admin
    data["manager"] = user.manager
    data["password"] = user.password

    return jsonify({"user": data})


@app.route("/user", methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin and not current_user.manager:
        return jsonify({"message": "You don't have permission"})

    data = request.get_json()

    password = generate_password_hash(data["password"], method="sha256")
    if data["admin"] == "True":
        admin = True
    else:
        admin = False
    if data["manager"] == "True":
        manager = True
    else:
        manager = False
    new_user = User(public_id=str(uuid.uuid4()), name=data["name"], password=password, admin=admin, manager=manager)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "New User created"})


@app.route("/user/<public_id>", methods=['PUT'])
@token_required
def update_user(current_user, public_id):
    if not current_user.admin and not current_user.manager:
        return jsonify({"message": "You don't have permission"})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"message": "No user found!"})

    data = request.get_json()

    if data["name"]:
        user.name = data["name"]
        db.session.commit()
    if data["admin"] == "True":
        user.admin = True
        db.session.commit()
    if data["password"]:
        password = generate_password_hash(data["password"], method="sha256")
        user.password = password
        db.session.commit()

    return jsonify({"message": "User Updated"})


@app.route("/user/<public_id>", methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin and not current_user.manager:
        return jsonify({"message": "You don't have permission"})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"message": "No user found!"})

    db.session.delete(user)
    db.session.commit()

    return jsonify({"message": "User was Deleted"})


@app.route("/login")
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response("Could not verify", 401, {"WWW-Authenticate": "Basic realm='Login required'"})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response("Could not verify", 401, {"WWW-Authenticate": "Basic realm='Login required'"})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {"public_id": user.public_id, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config["SECRET_KEY"])
        return jsonify({"token": token.decode('UTF-8')})

    return make_response("Could not verify", 401, {"WWW-Authenticate": "Basic realm='Login required'"})


@app.route("/expenses", methods=["GET"])
@token_required
def get_all_expenses(current_user):
    if current_user.admin:
        expenses = Expenses.query.filter_by().all()
    else:
        expenses = Expenses.query.filter_by(user_id=current_user.id).all()

    all_expenses = []

    for expense in expenses:
        expense_data = {}
        expense_data["id"] = expense.id
        expense_data["amount"] = expense.amount
        expense_data["date"] = expense.date
        expense_data["description"] = expense.description
        expense_data["comment"] = expense.comment
        if current_user.admin:
            expense_data["user_id"] = expense.user_id
        all_expenses.append(expense_data)

    return jsonify({"expenses": all_expenses})


@app.route("/expenses/<expense_id>", methods=["GET"])
@token_required
def get_expense(current_user, expense_id):

    if current_user.admin:
        expense = Expenses.query.filter_by(id=expense_id).first()
    else:
        expense = Expenses.query.filter_by(id=expense_id, user_id=current_user.id).first()

    if not expense:
        return jsonify({"message": "Expense not found"})

    expense_data = {}
    expense_data["id"] = expense.id
    expense_data["amount"] = expense.amount
    expense_data["date"] = expense.date
    expense_data["description"] = expense.description
    expense_data["comment"] = expense.comment

    return jsonify(expense_data)


@app.route("/expenses", methods=["POST"])
@token_required
def create_expenses(current_user):
    data = request.get_json()

    new_expense = Expenses(amount=data["amount"], date=datetime.datetime.now(), description=data["description"],
                           comment=data["comment"], user_id=current_user.public_id)
    db.session.add(new_expense)
    db.session.commit()
    return jsonify({"message": "Expense created"})


@app.route("/expenses/<expense_id>", methods=["PUT"])
@token_required
def update_expenses(current_user, expense_id):

    if current_user.admin:
        expense = Expenses.query.filter_by(id=expense_id).first()
    else:
        expense = Expenses.query.filter_by(id=expense_id, user_id=current_user.id).first()

    if not expense:
        return jsonify({"message": "Expense not found"})

    data = request.get_json()

    if data["amount"]:
        expense.amount = data["amount"]
        db.session.commit()
    if data["description"]:
        expense.description = data["description"]
        db.session.commit()
    if data["comment"]:
        expense.comment = data["comment"]
        db.session.commit()

    return jsonify({"message": "Expense Updated"})


@app.route("/expenses/<expense_id>", methods=["DELETE"])
@token_required
def delete_expenses(current_user, expense_id):

    if current_user.admin:
        expense = Expenses.query.filter_by(id=expense_id).first()
    else:
        expense = Expenses.query.filter_by(id=expense_id, user_id=current_user.id).first()

    if not expense:
        return jsonify({"message": "Expense not found"})

    db.session.delete(expense)
    db.session.commit()

    return jsonify({"message": "Expense Deleted"})


if __name__ == '__main__':
    app.run()
