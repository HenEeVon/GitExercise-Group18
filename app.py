from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_socketio import join_room, leave_room, send, SocketIO
import random
from string import ascii_uppercase
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, IntegerField
from wtforms.validators import DataRequired, NumberRange
from datetime import datetime
import pytz
from sqlalchemy import func, or_

MALAYSIA_TZ = pytz.timezone("Asia/Kuala_Lumpur")
UTC = pytz.utc

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///ebfit.db"
app.config["SECRET_KEY"] = "060226*"
db = SQLAlchemy(app)
socketio = SocketIO(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# User database
class User(UserMixin, db.Model):
    __tablename__ = "users"
    user_email = db.Column(db.String(255), primary_key=True)
    user_name = db.Column(db.String(255), nullable=False)
    gender = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def get_id(self):
        return self.user_email

class Admin(db.Model):
    __tablename__ = "admin"
    admin_email =  db.Column(db.String(255), primary_key=True)
    admin_name = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="admin")

class AdminRequest(db.Model):
    __tablename__ = "admin_request"
    approval_id = db.Column(db.Integer, primary_key=True)
    admin_email = db.Column(db.String(255), nullable=False)
    admin_name = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    join_reason = db.Column(db.Text, nullable=False)
    approval = db.Column(db.String(20), default="pending")  # pending / approved / rejected


class Posts(db.Model):
    __tablename__ = "posts"
    post_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(255), nullable=False)
    event_datetime = db.Column(db.String(255), nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    post_status = db.Column(db.String(20), default="open")
    participants = db.Column(db.Integer, nullable=False, default=1)

    user_email = db.Column(db.String(255), db.ForeignKey("users.user_email"), nullable=False)
    user = db.relationship("User", backref="posts")

    def local_date_posted(self):
        if self.date_posted is None:
            return None
        utc_time = UTC.localize(self.date_posted)
        malaysia_time = utc_time.astimezone(MALAYSIA_TZ)
        return malaysia_time


class JoinActivity(db.Model):
    __tablename__ = "join_activities"
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(255), db.ForeignKey("users.user_email"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("posts.post_id"), nullable=False)
    status = db.Column(db.String(20), default="pending")  # pending / accepted / rejected

    user = db.relationship("User", backref="join_activities")
    post = db.relationship("Posts", backref="join_activities")

# Activity Form database
class ActivityForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    content = TextAreaField("Content", validators=[DataRequired()])
    location = StringField("Location", validators=[DataRequired()])
    event_datetime = StringField("Event Date & Time (e.g. 2025-09-01, 8am - 10am)", validators=[DataRequired()])
    participants = IntegerField("Required Participants", validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField("Post")


# User loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(user_email=user_id).first()


# Home page
@app.route("/")
def home():
    return render_template("home.html")

# Register page
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        user_email = request.form["user_email"].strip().lower()
        user_name = request.form["user_name"]
        gender = request.form["gender"]
        password = request.form["password"]

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        new_user = User(user_email=user_email, user_name=user_name, gender=gender, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful! Please log in.")
            return redirect(url_for("login"))
        except IntegrityError:
            db.session.rollback()
            flash("Email already exists! Please log in.")

    return render_template("register.html")


# Login page
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["user_email"].strip().lower()
        password = request.form["password"]

        user = User.query.filter_by(user_email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash(f"Welcome {user.user_name}!")
            return redirect(url_for("posts"))

        flash("Invalid email or password!")

    return render_template("login.html")


# Logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.")
    return redirect(url_for("home"))



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
            flash("Email not found! Please register.")

    return render_template("login.html")


# Posts page
@app.route("/index")
def posts():
    posts = Posts.query.order_by(Posts.date_posted.desc()).all()
    for post in posts:
        if post.date_posted:
            utc_time = pytz.utc.localize(post.date_posted)
            post.local_date_posted_value = utc_time.astimezone(MALAYSIA_TZ)
        else:
            post.local_date_posted_value = None
    return render_template("index.html", posts=posts)


# Search feature
@app.route("/search", methods=["GET"])
def search():
    sport = (request.args.get("sport") or "").strip().lower()
    dateinpost = (request.args.get("date") or "").strip()

    searched = False
    results = []

    if sport and dateinpost:
        searched = True
        results = Posts.query.join(User).filter(
            or_(
                func.lower(Posts.title).like(f"%{sport}%"),
                func.lower(Posts.content).like(f"%{sport}%"),
                func.lower(Posts.location).like(f"%{sport}%"),
                func.lower(User.user_name).like(f"%{sport}%"),
            ),
            Posts.event_datetime.like(f"%{dateinpost}%")
        ).order_by(Posts.date_posted.desc()).all()

    elif sport:
        searched = True
        results = Posts.query.join(User).filter(
            or_(
                func.lower(Posts.title).like(f"%{sport}%"),
                func.lower(Posts.content).like(f"%{sport}%"),
                func.lower(Posts.location).like(f"%{sport}%"),
                func.lower(User.user_name).like(f"%{sport}%"),
            )
        ).order_by(Posts.date_posted.desc()).all()

    elif dateinpost:
        searched = True
        results = Posts.query.filter(
            Posts.event_datetime.like(f"%{dateinpost}%")
        ).order_by(Posts.date_posted.desc()).all()

    else:
        results = Posts.query.order_by(Posts.date_posted.desc()).all()

    for post in results:
        if post.date_posted:
            utc_time = pytz.utc.localize(post.date_posted)
            post.local_date_posted_value = utc_time.astimezone(MALAYSIA_TZ)
        else:
            post.local_date_posted_value = None

    return render_template("index.html", posts=results, searched=searched, sport=sport, date=dateinpost)

# Error page
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


# Create post form
@app.route("/create", methods=["GET", "POST"])
@login_required
def create():
    form = ActivityForm()
    if form.validate_on_submit():
        new_post = Posts(
            title=form.title.data,
            content=form.content.data,
            location=form.location.data,
            event_datetime=form.event_datetime.data,
            participants=form.participants.data,
            user_email=current_user.user_email
        )
        db.session.add(new_post)
        db.session.commit()
        flash("Post created successfully!", "success")
        return redirect(url_for("posts"))
    return render_template("create.html", form=form)


# Edit post
@app.route("/edit/<int:post_id>", methods=["GET", "POST"])
@login_required
def edit_post(post_id):
    post = Posts.query.get_or_404(post_id)
    form = ActivityForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        post.location = form.location.data
        post.event_datetime = form.event_datetime.data
        post.participants = form.participants.data
        db.session.commit()
        flash("Post has been updated!", "info")
        return redirect(url_for("post_detail", post_id=post.post_id))

    form.title.data = post.title
    form.content.data = post.content
    form.location.data = post.location
    form.event_datetime.data = post.event_datetime
    form.participants.data = post.participants
    return render_template("edit_post.html", form=form, post=post)


# Delete post
@app.route("/delete/<int:post_id>", methods=["POST"])
@login_required
def delete(post_id):
    post = Posts.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    flash("Post deleted successfully!", "danger")
    return redirect(url_for("posts"))


# Post detail
@app.route("/post/<int:post_id>")
def post_detail(post_id):
    post = Posts.query.get_or_404(post_id)
    post.local_date_posted_value = post.local_date_posted()
    join_activities = JoinActivity.query.filter_by(post_id=post.post_id).all()
    return render_template("post_detail.html", post=post, join_activities=join_activities)


# admin dashboard
@app.route("/admin_dashboard")
def admin_dashboard():
    if current_user.role != "admin":
        flash("Access denied.")
        return redirect(url_for("home"))

    requests = AdminRequest.query.filter_by(approval="pending").all()
    return render_template("admin_dashboard.html", requests=requests)

# admin users review
@app.route("/admin_users")
def users():
    return render_template("users.html")

# user notifications
@app.route("/notifications")
def notifications():
    return render_template("notifications.html")

# user profile
@app.route("/profile")
def profile():
    return render_template("profile.html")



# Join Activity
@app.route("/activityrequest/<int:post_id>", methods=["POST"])
@login_required
def activityrequest(post_id):
    post = Posts.query.get_or_404(post_id)

    if post.post_status == "closed":
        flash("This activity is already closed.")
        return redirect(url_for("post_detail", post_id=post.post_id))

    # Prevent duplicate request
    existing = JoinActivity.query.filter_by(user_email=current_user.user_email, post_id=post.post_id).first()
    if existing:
        flash("You already requested this activity. Please wait for the post owner to approve")
    else:
        join_act = JoinActivity(user_email=current_user.user_email, post_id=post.post_id)
        db.session.add(join_act)
        db.session.commit()
        flash("Your request has been sent to the post owner.")

    return redirect(url_for("post_detail", post_id=post.post_id))


# Handle Join Activity requests
@app.route("/handle-request/<int:request_id>/<string:decision>", methods=["POST"])
@login_required
def handle_request(request_id, decision):
    join_activity = JoinActivity.query.get_or_404(request_id)
    post = join_activity.post

    # Only post owner can handle
    if post.user_email != current_user.user_email:
        flash("You are not authorized to manage this request.")
        return redirect(url_for("post_detail", post_id=post.post_id))

    if post.post_status == "closed":
        flash("This activity is already closed.")
        return redirect(url_for("post_detail", post_id=post.post_id))

    if decision == "accept":
        accepted_count = JoinActivity.query.filter_by(post_id=post.post_id, status="accepted").count()

        if accepted_count < post.participants:
            join_activity.status = "accepted"
            flash(f"{join_activity.user.user_name} has been accepted!")

            accepted_count += 1
            if accepted_count >= post.participants:
                post.post_status = "closed"
                flash("The activity is now full and closed.")
        else:
            flash("This activity already has enough participants.")

    elif decision == "reject":
        join_activity.status = "rejected"
        flash(f"{join_activity.user.user_name} has been rejected.")

    db.session.commit()
    return redirect(url_for("post_detail", post_id=post.post_id))

#admin interface
#owner of the website
def create_owner():
    if not Admin.query.first():
        owner = Admin(
            admin_email="eewen@gmail.com",
            admin_name="Lee Ee Wen",
            password=generate_password_hash("aaaa", method="pbkdf2:sha256"),
            role="owner"
        )
        db.session.add(owner)
        db.session.commit()

# request to join admin
@app.route("/login_admin", methods=["GET", "POST"])
def login_admin():
    if request.method == "POST":
        email = request.form["admin_email"].strip().lower()
        password = request.form["password"]

        admin_instance = Admin.query.filter_by(admin_email=email).first()
        if admin_instance and check_password_hash(admin_instance.password, password):
            session["admin_email"] = admin_instance.admin_email
            session["role"] = admin_instance.role
            flash(f"Welcome {admin_instance.admin_name}!")
            return redirect(url_for("owner_approval"))
        else:
            flash("Invalid email or you are NOT admin !")

    return render_template("login_admin.html")


@app.route("/request_admin", methods=["GET", "POST"])
def request_admin():
    if request.method == "POST":
        email = request.form.get("admin_email", "").strip().lower()
        admin_name = request.form.get("admin_name", "")
        password = request.form.get("password", "")
        join_reason = request.form.get("join_reason", "")

        existing = AdminRequest.query.filter_by(admin_email=email).first()
        if existing:
            flash("You already submitted a request. Please wait for approval.")
        else:
            new_request = AdminRequest(
                admin_email=email,
                admin_name=admin_name,
                password=generate_password_hash(password, method="pbkdf2:sha256"),
                join_reason=join_reason,
                approval="pending"
            )
            db.session.add(new_request)
            db.session.commit()
            flash("Your request has been submitted and is pending approval.")

        return redirect(url_for("login_admin"))

    return render_template("request_admin.html")

@app.route("/handle-request/<int:approval_id>", methods=["GET", "POST"])
def handle_request_admin(approval_id):
    # Must be logged in
    if "admin_email" not in session:
        flash("You must log in first.")
        return redirect(url_for("login_admin"))

    # Only owner can approve
    current_admin = Admin.query.get(session["admin_email"])
    if not current_admin or current_admin.role != "owner":
        flash("You do not have permission to approve requests.")
        return redirect(url_for("owner_approval"))

    join_request = AdminRequest.query.get_or_404(approval_id)

    if request.method == "POST":
        decision = request.form.get("decision")
        if decision == "accept":
            join_request.approval = "accepted"
            if not Admin.query.get(join_request.admin_email):
                new_admin = Admin(
                    admin_email=join_request.admin_email,
                    admin_name=join_request.admin_name,
                    password=join_request.password,
                    role="admin"
                )
                db.session.add(new_admin)
            flash(f"{join_request.admin_name} has been approved as admin.")
        elif decision == "reject":
            join_request.approval = "rejected"
            flash(f"Request from {join_request.admin_name} has been rejected.")

        db.session.commit()
        return redirect(url_for("owner_approval"))

    # GET → show details
    return render_template("join_admin.html", request=join_request)


@app.route("/owner_approval")
def owner_approval():
    if "admin_email" not in session:
        flash("You must log in first.")
        return redirect(url_for("login_admin"))

    # Only show requests if owner is logged in
    current_admin = Admin.query.get(session["admin_email"])
    if not current_admin:
        flash("Invalid session. Please log in again.")
        return redirect(url_for("login_admin"))

    if current_admin.role == "owner":
        requests = AdminRequest.query.filter_by(approval="pending").all()
    else:
        requests = []  # Normal admins can’t see approval requests

    return render_template("owner_approval.html", admin=current_admin, requests=requests)



# Run app
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        create_owner()
        socketio.run(app, debug=True)
