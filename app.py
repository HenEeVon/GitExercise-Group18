from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired
from datetime import datetime
import pytz

MALAYSIA_TZ = pytz.timezone("Asia/Kuala_Lumpur")
UTC = pytz.utc

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///ebfit.db"
app.config["SECRET_KEY"] = "060226*"
db = SQLAlchemy(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# ---------------------------
# Database Models
# ---------------------------
class User(UserMixin, db.Model):
    __tablename__ = "users"
    user_email = db.Column(db.String(255), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    gender = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user")  # "user" or "admin"

    def get_id(self):
        return self.user_email


class AdminRequest(db.Model):
    __tablename__ = "admin_requests"
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(255), db.ForeignKey("users.user_email"), nullable=False)
    join_reason = db.Column(db.Text, nullable=False)
    approval = db.Column(db.String(20), default="pending")  # pending / approved / rejected

    user = db.relationship("User", backref="admin_requests")

# posts database model
class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    content = db.Column(db.Text)
    author = db.Column(db.String(255))
    location = db.Column(db.String(255))
    event_datetime = db.Column(db.String(255))
    date_posted = db.Column(db.DateTime, default=datetime.utcnow) 

    def local_date_posted(self):
        if self.date_posted is None:
            return None
    
        utc_time = UTC.localize(self.date_posted)
        malaysia_time = utc_time.astimezone(MALAYSIA_TZ)
        return malaysia_time


# Flask-WTF form
class ActivityForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    content = TextAreaField("Content", validators=[DataRequired()])
    location = StringField("Location", validators=[DataRequired()])
    event_datetime = StringField("Event Date & Time (e.g. 2025-09-01, 8am - 10am)", validators=[DataRequired()])
    author = StringField("Author")
    submit = SubmitField("Post")



# ---------------------------
# Flask-Login User Loader
# ---------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(user_email=user_id).first()


# ---------------------------
# Routes
# ---------------------------
@app.route("/")
def home():
    return render_template("home.html")


# User registration
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


# Login (works for both user and admin)
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["user_email"].strip().lower()
        password = request.form["password"]

        user = User.query.filter_by(user_email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash(f"Welcome {user.name}!")

            if user.role == "admin":
                return redirect(url_for("admin_dashboard"))
            else:
                return redirect(url_for("home"))

        flash("Invalid email or password!")

    return render_template("login.html")


# User homepage
@app.route("/user-home")
@login_required
def user_home():
    return render_template("user_home.html")


# Admin dashboard (manage requests)
@app.route("/admin-dashboard")
@login_required
def admin_dashboard():
    if current_user.role != "admin":
        flash("Access denied.")
        return redirect(url_for("home"))

    requests = AdminRequest.query.filter_by(approval="pending").all()
    return render_template("admin_dashboard.html", requests=requests)


# Reset password
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


# Logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.")
    return redirect(url_for("home"))


# Request admin access
@app.route("/request-admin", methods=["GET", "POST"])
@login_required
def request_admin():
    if request.method == "POST":
        reason = request.form["reason"]
        existing_request = AdminRequest.query.filter_by(
            user_email=current_user.user_email, approval="pending"
        ).first()

        if existing_request:
            flash("You already have a pending request.")
        else:
            new_request = AdminRequest(user_email=current_user.user_email, join_reason=reason)
            db.session.add(new_request)
            db.session.commit()
            flash("Your request has been submitted.")

        return redirect(url_for("user_home"))

    return render_template("request_admin.html")


# Approve request
@app.route("/approve-admin/<int:request_id>", methods=["POST"])
@login_required
def approve_admin(request_id):
    if current_user.role != "admin":
        flash("Access denied.")
        return redirect(url_for("home"))

    req = AdminRequest.query.get_or_404(request_id)
    req.approval = "approved"

    user = User.query.filter_by(user_email=req.user_email).first()
    if user:
        user.role = "admin"

    db.session.commit()
    flash(f"{user.name} is now an admin.")
    return redirect(url_for("admin_dashboard"))


# Reject request
@app.route("/reject-admin/<int:request_id>", methods=["POST"])
@login_required
def reject_admin(request_id):
    if current_user.role != "admin":
        flash("Access denied.")
        return redirect(url_for("home"))

    req = AdminRequest.query.get_or_404(request_id)
    req.approval = "rejected"
    db.session.commit()

    flash("Request rejected.")
    return redirect(url_for("admin_dashboard"))

# post interface
@app.route("/")
def home():
    posts = Posts.query.order_by(Posts.date_posted.desc()).all()
    for post in posts:
        if post.date_posted:
            utc_time = pytz.utc.localize(post.date_posted)
            post.local_date_posted_value = utc_time.astimezone(MALAYSIA_TZ)
        else:
            post.local_date_posted_value = None
    return render_template("index.html", posts=posts)

# error page
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404 


# create post form
@app.route("/create", methods=["GET", "POST"])
def create():
    form = ActivityForm()
    if form.validate_on_submit():
        new_post = Posts(
            title=form.title.data,
            content=form.content.data,
            location=form.location.data,
            event_datetime=form.event_datetime.data,
            author=form.author.data if form.author.data else "Anonymous"
        )
        db.session.add(new_post)
        db.session.commit()
        flash("Post created successfully!","success")
        return redirect(url_for("home"))
    return render_template("create.html", form=form)


# edit post
@app.route("/edit/<int:post_id>", methods=[ "GET", "POST" ])
def edit_post(post_id):
    post = Posts.query.get_or_404(post_id)
    form = ActivityForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.author = form.author.data
        post.content = form.content.data
        post.location = form.location.data
        post.event_datetime = form.event_datetime.data
        # update database
        db.session.commit()
        flash("Post Has Been Updated!","info")
        return redirect(url_for("post_detail",post_id=post.id))
    form.title.data = post.title
    form.author.data = post.author
    form.content.data = post.content
    form.location.data = post.location
    form.event_datetime.data = post.event_datetime
    return render_template("edit_post.html",form=form, post=post )



# delete post
@app.route("/delete/<int:post_id>", methods=["POST"])
def delete(post_id):
    post = Posts.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    flash("Post deleted successfully!","danger")
    return redirect(url_for("home"))

# detail post
@app.route("/post/<int:post_id>")
def post_detail(post_id):
    post = Posts.query.get_or_404(post_id)
    post.local_date_posted_value = post.local_date_posted()
    return render_template("post_detail.html", post=post)


# ---------------------------
# Run
# ---------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        app.run(debug=True)