from flask import Flask, render_template, url_for, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)

# Configure database (single SQLite file)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///user.db"
app.config["SECRET_KEY"] = "060226*"   # Needed for flash messages
db = SQLAlchemy(app)


# User database
class User(db.Model):
    __tablename__ = "users"
    user_email = db.Column(db.String(255), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    gender = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(255), nullable=False)


# Admin database
class Admin(db.Model):
    __tablename__ = "admins"
    admin_email = db.Column(db.String(255), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)


# define routes
@app.route("/")
def home():
    return render_template("home.html")


# Register User
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        user_email = request.form["user_email"].strip().lower()
        name = request.form["name"]
        gender = request.form["gender"]
        password = request.form["password"]

        new_user = User(user_email=user_email, name=name, gender=gender, password=password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful! Please log in.")
            return redirect(url_for("login"))
        except IntegrityError:
            db.session.rollback()
            flash("Email already exists! Please log in.")

    return render_template("register.html")


# Login User
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["user_email"].strip().lower()
        password = request.form["password"]

        user = User.query.filter_by(user_email=email).first()

        if user:
            if user.password == password:
                flash(f"Welcome {user.name}!")
                return redirect(url_for("home"))
            else:
                flash("Incorrect password! Try again.")
        else:
            flash("Email not found! Please register first.")

    return render_template("login.html")


# Reset Password
@app.route("/resetpass", methods=["GET", "POST"])
def resetpass():
    if request.method == "POST":
        user_email = request.form.get("email")
        new_password = request.form.get("new_password")

        if not user_email or not new_password:
            flash("Email and new password are required!")
            return redirect(url_for("resetpass"))

        user = User.query.filter_by(user_email=user_email).first()
        if user:
            user.password = new_password
            db.session.commit()
            flash("Password updated successfully! Please log in.")
            return redirect(url_for("login"))
        else:
            flash("Email not found! Please type again.")

    return render_template("login.html")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create database if not exist
        app.run (debug=True)
