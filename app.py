from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_socketio import join_room, send, SocketIO
import random
from string import ascii_uppercase
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, SubmitField, SelectField, TextAreaField, IntegerField
from wtforms.validators import DataRequired, NumberRange, Length, Optional
from datetime import datetime
from PIL import Image
import pytz
import os, secrets
from sqlalchemy import func, or_, asc

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
    image_file = db.Column(db.String(255), nullable=True, default="default.png")
    bio = db.Column(db.Text, nullable=True)
    

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

#Chat database
class ChatMessage(db.Model):
    tablename = "chat_messages"
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, nullable=False, index=True)

    conversation = db.Column(db.String(600), nullable=False, index=True)

    sender_email = db.Column(db.String(255), nullable=False)
    sender_name = db.Column(db.String(255), nullable=False)
    text = db.Column(db.Text, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

#Update Profile
class UpdateProfileForm(FlaskForm):
    full_name = StringField("Full name", validators=[DataRequired(), Length(min=5, max=20)])
    gender = SelectField("Gender", choices=[("male","Male"),("female","Female"), ("other","Other")], 
                         validators=[DataRequired()])
    bio = TextAreaField("Bio", validators=[Optional(), Length(max=1000)])
    picture = FileField("Profile picture", validators=[FileAllowed(["jpg","png"])])
    submit = SubmitField("Save changes")

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

#route 
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

    owner_conversations = []
    if current_user.is_authenticated and current_user.user_email.lower() == post.user_email.lower():
        partners = db.session.query(ChatMessage.sender_email).filter_by(post_id=post.post_id).distinct()
        for (email,) in partners:
            if email.lower() != post.user_email.lower():
                user = User.query.get(email)
                owner_conversations.append({"email": email, "name":user.user_name if user else email})

    return render_template("post_detail.html", post=post, join_activities=join_activities, owner_conversations=owner_conversations)

#Chat feature
def conversation_key(a_email: str, b_email: str) -> str:
    return "|".join(sorted([a_email.lower(), b_email.lower()]))

@app.route("/chat/<int:post_id>/<partner_email>")
def chat_with_user(post_id, partner_email):
    post = Posts.query.get_or_404(post_id)
    owner_email = post.user_email.lower()
    current_email = current_user.user_email.lower()
    partner_email = partner_email.lower()

    if current_email != owner_email and partner_email != owner_email:
        return redirect(url_for("chat_with_user", post_id=post_id, partner_email=owner_email))

    conv = conversation_key(current_email, partner_email)
    room = f"post-{post_id}-{conv}"

    messages = (ChatMessage.query.filter_by(post_id=post_id, conversation=conv).order_by(asc(ChatMessage.created_at)).all())

    partner_user = User.query.get(partner_email)
    partner_name = partner_user.user_name if partner_user else partner_email

    if current_email == owner_email:
        header_name = partner_name
    else:
        header_name = post.user.user_name

    return render_template("chat.html",post=post, room=room, username=current_user.user_name,header_name=header_name, 
                           messages=messages, post_id=post_id, partner_email=partner_email)

@socketio.on("join")
def on_join(data):
    room = data.get("room")
    if room:
        print("JOIN ->", current_user.user_email, "to", room)
    join_room(room)
    send(f"{current_user.user_name} joined the chat.", to=room)

@socketio.on("send_message")
def on_send_message(data):
    room = (data or {}).get("room")
    text = ((data or {}).get("message") or "").strip()
    post_id = (data or {}).get("post_id")
    partner = ((data or {}).get("partner_email")or "").lower().strip()

    if not (room and text and post_id and partner):
        return

    current_email = current_user.user_email.lower()
    conv = conversation_key(current_email,partner)

    msg = ChatMessage(post_id=int(post_id), conversation=conv, sender_email=current_user.user_email, sender_name=current_user.user_name, text=text)
    db.session.add(msg)
    db.session.commit()

    send({"user": msg.sender_name, "text": msg.text}, to=room)

# Notifications
@app.route("/notifications")
def notifications():
    return render_template("notifications.html")

#My Profiled
@app.route("/profile")
@login_required
def profile():
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template("profile.html", title='Profile', image_file=image_file)

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, "static/profile_pics", picture_fn)
    form_picture.save(picture_path)
    return picture_fn

#View profile
@app.route("/profile")
@login_required
def profile():
    recent_posts = (Posts.query.filter_by(user_email=current_user.user_email).order_by(Posts.date_posted.desc()).all())

    if current_user.image_file:
        image_url = url_for("static", filename=f"profile_pics/{current_user.image_file}")
    else:
        image_url = url_for("static", filename="profile_pics/default.png")

    for post in recent_posts:
        if post.date_posted:
            utc_time = pytz.utc.localize(post.date_posted)
            post.local_date_posted_value = utc_time.time.astimezone(MALAYSIA_TZ)
        else:
            post.local_date_posted_value = None

    return render_template("profile.html", user=current_user, image_url=image_url, recent_posts=recent_posts)

@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def profile_edit():
    from forms import UpdateProfileForm

    form = UpdateProfileForm()

    if form.validate_on_submit():
        current_user.user_name = form.full_name.data
        current_user.gender = form.gender.data
        current_user.bio = form.bio.data or None

        if form.picture.data:
            filename = save_profile_picture(form.picture.data)
            current_user.image_file = filename

        db.session.commit()
        flash("Profile updated.", "success")
        return redirect(url_for("profile"))
    
    if not form.is_submitted():
        form.full_name.data = current_user.user_name
        form.gender.data = current_user.gender
        form.bio.data = current_user.bio

    image_url = (url_for("static", filename=f"profile_pics/{current_user.image_file}"))
    if current_user.image_file 
    else url_for("static", filename="profile_pics/default.png")

    return render_template("edit_profile.html",form=form, image_url=image_url)


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
