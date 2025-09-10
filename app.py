from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
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

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# USer db
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


class JoinRequest(db.Model):
    __tablename__ = "join_requests"
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(255), db.ForeignKey("users.user_email"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("posts.post_id"), nullable=False)
    status = db.Column(db.String(20), default="pending")  # pending / accepted / rejected

    user = db.relationship("User", backref="join_requests")
    post = db.relationship("Posts", backref="join_requests")


# Activity Form database
class ActivityForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    content = TextAreaField("Content", validators=[DataRequired()])
    location = StringField("Location", validators=[DataRequired()])
    event_datetime = StringField("Event Date & Time (e.g. 2025-09-01, 8am - 10am)", validators=[DataRequired()])
    participants = IntegerField("Required Participants", validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField("Post")


# User loader-
@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(user_email=user_id).first()

# Home, front page
@app.route("/")
def home():
    return render_template("home.html")

# register page
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
            return redirect(url_for("posts"))

        flash("Invalid email or password!")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.")
    return redirect(url_for("home"))

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

#Search feature
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
                func.lower(User.name).like(f"%{sport}%"),
        ),Posts.event_datetime.like(f"%{dateinpost}%")).order_by(Posts.date_posted.desc()).all()
    
    elif sport:
        searched = True
        results = Posts.query.join(User).filter(
            or_(
                func.lower(Posts.title).like(f"%{sport}%"),
                func.lower(Posts.content).like(f"%{sport}%"),
                func.lower(Posts.location).like(f"%{sport}%"),
                func.lower(User.name).like(f"%{sport}%"),
            )).order_by(Posts.date_posted.desc()).all()
        
    elif dateinpost:
        searched = True
        results = Posts.query.filter(
            Posts.event_datetime.like(f"%{dateinpost}%")).order_by(Posts.date_posted.desc()).all()

    else:
        results = Posts.query.order_by(Posts.date_posted.desc()).all()

    for post in results:
        if post.date_posted:
            utc_time = pytz.utc.localize(post.date_posted)
            post.local_date_posted_value = utc_time.astimezone(MALAYSIA_TZ)
        else:
            post.local_date_posted_value = None

    return render_template("index.html",posts=results,searched=searched,sport=sport,date=dateinpost)

# error page
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

# create post form
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


@app.route("/delete/<int:post_id>", methods=["POST"])
@login_required
def delete(post_id):
    post = Posts.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    flash("Post deleted successfully!", "danger")
    return redirect(url_for("posts"))


@app.route("/post/<int:post_id>")
def post_detail(post_id):
    post = Posts.query.get_or_404(post_id)
    post.local_date_posted_value = post.local_date_posted()
    join_requests = JoinRequest.query.filter_by(post_id=post.post_id).all()
    return render_template("post_detail.html", post=post, join_requests=join_requests)

# Join Activity
@app.route("/activityrequest/<int:post_id>", methods=["POST"])
@login_required
def activityrequest(post_id):
    post = Posts.query.get_or_404(post_id)

    if post.post_status == "closed":
        flash("This activity is already closed.")
        return redirect(url_for("post_detail", post_id=post.post_id))

    # Prevent duplicate request
    existing = JoinRequest.query.filter_by(user_email=current_user.user_email, post_id=post.post_id).first()
    if existing:
        flash("You already requested to join this activity.")
    else:
        join_req = JoinRequest(user_email=current_user.user_email, post_id=post.post_id)
        db.session.add(join_req)
        db.session.commit()
        flash("Your request has been sent to the post owner.")

    return redirect(url_for("post_detail", post_id=post.post_id))


@app.route("/handle-request/<int:request_id>/<string:decision>", methods=["POST"])
@login_required
def handle_request(request_id, decision):
    join_request = JoinRequest.query.get_or_404(request_id)
    post = join_request.post

    # Only post owner can handle
    if post.user_email != current_user.user_email:
        flash("You are not authorized to manage this request.")
        return redirect(url_for("post_detail", post_id=post.post_id))

    if post.post_status == "closed":
        flash("This activity is already closed.")
        return redirect(url_for("post_detail", post_id=post.post_id))

    if decision == "accept":
        accepted_count = JoinRequest.query.filter_by(post_id=post.post_id, status="accepted").count()

        if accepted_count < post.participants:
            join_request.status = "accepted"
            flash(f"{join_request.user.name} has been accepted!")

            accepted_count += 1
            if accepted_count >= post.participants:
                post.post_status = "closed"
                flash("The activity is now full and closed.")
        else:
            flash("This activity already has enough participants.")

    elif decision == "reject":
        join_request.status = "rejected"
        flash(f"{join_request.user.name} has been rejected.")

    db.session.commit()
    return redirect(url_for("post_detail", post_id=post.post_id))

# Run 
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        app.run(debug=True)

