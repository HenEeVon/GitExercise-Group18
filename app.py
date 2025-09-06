from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///user.db"
app.config["SECRET_KEY"] = "060226*"  # Needed for session management and flash messages
db = SQLAlchemy(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# user database
class User(UserMixin, db.Model):
    __tablename__ = "users"
    user_email = db.Column(db.String(255), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    gender = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def get_id(self):
        return self.user_email #create currently login user


class Admin(UserMixin, db.Model):
    __tablename__ = "admins"
    admin_email = db.Column(db.String(255), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def get_id(self):
        return self.admin_email
    
class Admin_requests(UserMixin, db.Model):
    __tablename__ = "admin_request"
    admin_request_id = db.Column(db.Integer, primary_key=True)
    admin_email = db.Column(db.String(255), db.ForeignKey('users.email'), nullable=False)
    join_reason = db.Column(db.Text, nullable=False)
    admin_approval = db.Column(db.Boolean, nullable=True, default=None) 

    def __repr__(self):
        return f"<AdminRequest {self.admin_email} - {self.admin_approval}>"
    # self.admin_email： show user email who requested admin access
    # self.admin_approval: show the request if true=approved, false(rejected)

# load user
@login_manager.user_loader
def load_user(user_id):
    user = User.query.filter_by(user_email=user_id).first()
    if user:
        return user
    return Admin.query.filter_by(admin_email=user_id).first()

# home
@app.route("/")
def home():
    return render_template("home.html")

# user
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        user_email = request.form["user_email"].strip().lower()
        name = request.form["name"]
        gender = request.form["gender"]
        password = request.form["password"]

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        new_user = User(user_email=user_email, name=name, gender=gender, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful! Please log in.")
            return redirect(url_for("login"))
        except IntegrityError:
            db.session.rollback()
            flash("Email already exists! Please log in.")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["user_email"].strip().lower()
        password = request.form["password"]

        user = User.query.filter_by(user_email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash(f"Welcome {user.name}!")
            return redirect(url_for("home"))
        else:
            flash("Invalid email or password!")

    return render_template("login.html")


@app.route("/resetpass", methods=["GET", "POST"])
def resetpass():
    if request.method == "POST":
        email = request.form.get("email").strip().lower()
        new_password = request.form.get("new_password")

        if not email or not new_password:
            flash("Email and new password are required!")
            return redirect(url_for("resetpass"))

        user = User.query.filter_by(user_email=email).first()
        if user:
            user.password = generate_password_hash(new_password, method="pbkdf2:sha256")
            db.session.commit()
            flash("Password updated successfully! Please log in.")
            return redirect(url_for("login"))
        else:
            flash("Email not found!")

    return render_template("resetpass.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.")
    return redirect(url_for("home"))

# admin
@app.route("/request_admin", methods=["GET", "POST"])
def request_admin():
    if request.method == "POST":
        admin_email = request.form["admin_email"].strip().lower()
        name = request.form["name"]
        password = request.form["password"]

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        new_admin = Admin(admin_email=admin_email, name=name, password=hashed_password)

        try:
            db.session.add(new_admin)
            db.session.commit()
            flash("Admin registration successful! Please log in.")
            return redirect(url_for("login_admin"))
        except IntegrityError:
            db.session.rollback()
            flash("Email already exists! Please log in.")

    return render_template("request_admin.html")


@app.route("/login_admin", methods=["GET", "POST"])
def login_admin():
    if request.method == "POST":
        email = request.form["admin_email"].strip().lower()
        password = request.form["password"]

        admin_instance = Admin.query.filter_by(admin_email=email).first()
        if admin_instance and check_password_hash(admin_instance.password, password):
            login_user(admin_instance)
            flash(f"Welcome {admin_instance.name}!")
            return redirect(url_for("home"))
        else:
            flash("Invalid email or you are NOT admin !")

    return render_template("login_admin.html")

# run
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        app.run(debug=True)
