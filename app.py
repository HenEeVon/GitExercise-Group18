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
from wtforms import StringField, SubmitField, TextAreaField, IntegerField, DateField, TimeField,  SelectField
from wtforms.validators import DataRequired, NumberRange, Length, Optional
from flask_wtf.file import FileField, FileAllowed
from datetime import datetime
from PIL import Image
import pytz
import os, secrets
from sqlalchemy import func, or_, asc, case
import csv 
import os
MALAYSIA_TZ = pytz.timezone("Asia/Kuala_Lumpur")
UTC = pytz.utc

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///ebfit.db"
app.config["SECRET_KEY"] = "060226*"
db = SQLAlchemy(app)
socketio = SocketIO(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# User database
class User(UserMixin, db.Model):
    __tablename__ = "users"
    email = db.Column(db.String(255), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    gender = db.Column(db.String(50), nullable=False)
    sport_level = db.Column(db.String(255), nullable=False)
    security_question = db.Column(db.String(255), nullable=False)
    security_answer = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=True)
    image_file = db.Column(db.String(255), nullable=True, default="default.png")
    bio = db.Column(db.Text, nullable=True)
    role = db.Column(db.String(20), default="user") 
    

    def get_id(self):
        return self.email

class AdminRequest(db.Model):
    __tablename__ = "admin_request"
    approval_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False, unique=True)
    name = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    join_reason = db.Column(db.Text, nullable=False)
    approval = db.Column(db.String(20), default="pending")  # pending / approved / rejected
    security_question = db.Column(db.String(255), nullable=False) 
    security_answer = db.Column(db.String(255), nullable=False)  


class Posts(db.Model):
    __tablename__ = "posts"
    post_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(255), nullable=False)

    event_date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)

    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    post_status = db.Column(db.String(20), default="open")
    participants = db.Column(db.Integer, nullable=False, default=1)

    email = db.Column(db.String(255), db.ForeignKey("users.email"), nullable=False)
    user = db.relationship("User", backref="posts")



class JoinActivity(db.Model):
    __tablename__ = "join_activities"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), db.ForeignKey("users.email"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("posts.post_id"), nullable=False)
    status = db.Column(db.String(20), default="pending")  # pending / accepted / rejected

    user = db.relationship("User", backref="join_activities")
    post = db.relationship("Posts", backref="join_activities")

def load_locations():
    csv_path = os.path.join("instance", "locations.csv")
    choices = []

    if os.path.exists(csv_path):
        locations = []
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("name") and row.get("distance"):
                    try:
                        name = row["name"].strip()
                        distance = float(row["distance"])
                        locations.append((name, f"{name} ({distance} km)", distance))
                    except ValueError:
                        continue  # skip invalid distances

        # sort by distance
        locations.sort(key=lambda x: x[2])
        # only keep (value, label)
        choices = [(loc[0], loc[1]) for loc in locations]

    return choices

    
# Activity Form database
class ActivityForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    content = TextAreaField("Content", validators=[DataRequired()])
    location = SelectField("Location", choices=[],validators=[DataRequired()])

    event_date = DateField("Activity Date", format="%Y-%m-%d", validators=[DataRequired()])
    start_time = TimeField("Start Time", format="%H:%M", validators=[DataRequired()])
    end_time = TimeField("End Time", format="%H:%M", validators=[DataRequired()])

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
    name = StringField("Full Name", validators=[DataRequired(), Length(min=2, max=50)])
    gender = SelectField("Gender", choices=[("Male", "Male"), ("Female", "Female"), ("Other", "Other")])
    bio = TextAreaField("Bio", validators=[Length(max=200)])
    picture = FileField("Update Profile Picture", validators=[FileAllowed(["jpg", "png"])])
    submit = SubmitField("Update")


# User loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(email=user_id).first()

@app.template_filter("datetimeformat")
def datetimeformat(value, format="%d/%m/%Y"):
    """Convert YYYY-MM-DD or datetime into DD/MM/YYYY"""
    if not value:
        return ""
    try:
        # If value is a datetime
        if isinstance(value, datetime):
            return value.strftime(format)

        # If stored as string (like event_datetime)
        if isinstance(value, str):
            try:
                return datetime.strptime(value, "%Y-%m-%d").strftime(format)
            except ValueError:
                return value  # return raw if it’s not in date format
    except Exception:
        return value



# Home page
@app.route("/")
def home():
    return render_template("home.html")


#register page
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Get and normalize form data
        email = request.form.get("email", "").strip().lower()
        name = request.form.get("name", "").strip()
        gender = request.form.get("gender", "").strip()
        sport_level = request.form.get("sport_level", "").strip()
        security_question = request.form.get("security_question", "").strip().lower()
        security_answer = request.form.get("security_answer", "").strip().lower()
        password = request.form.get("password", "").strip()

        if not (email and name and password):
            flash("Please fill in all required fields.")
            return redirect(url_for("register"))

        # Hash the password
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

        # Create user
        new_user = User(
            email=email,
            name=name,
            gender=gender,
            sport_level=sport_level,
            security_question=security_question,
            security_answer=security_answer,
            password=hashed_password,
            role="user"  # default role
        )

        try:
            db.session.add(new_user)
            db.session.commit()

            # Automatically log in new user
            login_user(new_user)
            flash(f"Registration successful! Welcome {new_user.name}.")
            return redirect(url_for("posts"))

        except IntegrityError:
            db.session.rollback()
            flash("Email already exists. Please log in.")
            return redirect(url_for("login"))

    return render_template("register.html",question=question)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        user = User.query.filter_by(email=email).first()

        if not user:
            flash("Email not found.")
            return redirect(url_for("login"))

        if not check_password_hash(user.password, password):
            flash("Incorrect password. Please try again")
            return redirect(url_for("login"))

        # Login successful
        login_user(user)
        flash(f"Welcome back, {user.name}!")

        if user.role in ["admin", "both"]:
            return redirect(url_for("admin_approval"))
        return redirect(url_for("posts"))

    return render_template("login.html")


question = {
    "pet": "What was your first pet name?",
    "car": "What was your first car?",
    "hospital": "What hospital name were you born in?",
    "city": "What city were you born in?",
    "girlfriend": "What was your first ex girlfriend's name?",
    "boyfriend": "What was your first ex boyfriend's name?",
    "school": "What was the name of your first school?",
    "book": "What was your favorite childhood book?"
}

@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        step = request.form.get("current")

        # Step 1: Enter email
        if step == "email":
            email = request.form.get("email", "").strip().lower()
            user = User.query.filter_by(email=email).first()

            if not user:
                flash("Email not found.")
                return render_template("login.html", open_reset_modal=True)

            security_question = question.get(user.security_question.strip().lower(), "Security question not found")

            return render_template(
                "login.html",
                open_reset_modal=True,
                email=email,
                security_question=security_question
            )

        # Step 2: Submit answer & new password
        elif step == "reset":
            email = request.form.get("email", "").strip().lower()
            answer = request.form.get("security_answer", "").strip().lower()
            new_password = request.form.get("new_password", "")

            user = User.query.filter_by(email=email).first()
            if not user:
                flash("Email not found.")
                return render_template("login.html", open_reset_modal=True)

            if user.security_answer.lower() == answer:
                user.password = generate_password_hash(new_password, method="pbkdf2:sha256")
                db.session.commit()
                flash("Password updated successfully!")
                return redirect(url_for("login"))
            else:
                flash("Security answer incorrect.")
                return render_template(
                    "login.html",
                    open_reset_modal=True,
                    email=email,
                    security_question = question.get(user.security_question.strip().lower(), "Security question not found")
                )

    # Default: show reset modal
    return render_template("login.html", open_reset_modal=True,question=question)


# Posts page
@app.route("/index")
@login_required
def posts():
    # Load all posts
    posts = Posts.query.order_by(Posts.date_posted.desc()).all()

    # Convert UTC to Malaysia timezone
    for post in posts:
        if post.date_posted:
            utc_time = pytz.utc.localize(post.date_posted)
            post.local_date_posted_value = utc_time.astimezone(MALAYSIA_TZ)
        else:
            post.local_date_posted_value = None

    return render_template(
        "index.html",
        posts=posts,
        is_admin=current_user.role == "admin" if current_user.is_authenticated else False
    )


# Search feature
@app.route("/search", methods=["GET"])
def search():
    sport = (request.args.get("sport") or "").strip().lower()
    dateinpost = (request.args.get("date") or "").strip()

    searched = False
    query = Posts.query.join(User)

    # Filter by sport if provided
    if sport:
        searched = True
        query = query.filter(
            or_(
                func.lower(Posts.title).like(f"%{sport}%"),
                func.lower(Posts.content).like(f"%{sport}%"),
                func.lower(Posts.location).like(f"%{sport}%"),
                func.lower(User.name).like(f"%{sport}%")
            )
        )

    # Filter by date if provided
    if dateinpost:
        searched = True
        try:
            date_obj = datetime.strptime(dateinpost, "%Y-%m-%d").date()
            query = query.filter(Posts.event_date == date_obj)
        except ValueError:
            flash("Invalid date format. Please use YYYY-MM-DD.")

    # Execute query
    results = query.order_by(Posts.date_posted.desc()).all()

    # Convert posted date to Malaysia timezone
    for post in results:
        if post.date_posted:
            utc_time = pytz.utc.localize(post.date_posted)
            post.local_date_posted_value = utc_time.astimezone(MALAYSIA_TZ)
        else:
            post.local_date_posted_value = None

    return render_template(
        "index.html",  # keep your interface the same
        posts=results,
        searched=searched,
        sport=sport,
        date=dateinpost
    )



# Error page
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


# Create post form
@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    form = ActivityForm()
    
    # Force reload of locations for this form instance (add safe defaults for testing)
    form.location.choices = load_locations()
    if not form.location.choices or form.location.choices == [("none", "--Please select a location--")]:
        form.location.choices = [("Gym", "Gym"), ("Pool", "Pool")]  # fallback choices
    
    if form.validate_on_submit():
        # Debug: show submitted data
        print("Form validated! Data:", form.data)
        
        try:
            new_post = Posts(
                title=form.title.data,
                content=form.content.data,
                location=form.location.data,
                event_date=form.event_date.data,
                start_time=form.start_time.data,
                end_time=form.end_time.data,
                participants=form.participants.data,
                email=current_user.email,
            )
            db.session.add(new_post)
            db.session.commit()
            flash("Post created successfully!", "success")
            return redirect(url_for("posts"))
        except Exception as e:
            print("Error creating post:", e)
            flash(f"Error creating post: {e}", "danger")
    else:
        if request.method == "POST":
            # Form did not validate
            print("Form validation failed. Errors:", form.errors)
            flash(f"Form errors: {form.errors}", "danger")
    
    return render_template("create.html", form=form)


# Edit post
@app.route("/edit/<int:post_id>", methods=["GET", "POST"])
@login_required
def edit_post(post_id):
    post = Posts.query.get_or_404(post_id)
    form = ActivityForm()

    # ✅ Reload choices for edit form too
    form.location.choices = load_locations()
    if not form.location.choices or form.location.choices == [("none", "--Please select a location--")]:
        form.location.choices = [("Gym", "Gym"), ("Pool", "Pool")]

    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        post.location = form.location.data
        post.event_date = form.event_date.data
        post.start_time = form.start_time.data
        post.end_time = form.end_time.data
        post.participants = form.participants.data

        db.session.commit()
        flash("Post has been updated!", "info")
        return redirect(url_for("post_detail", post_id=post.post_id))

    if request.method == "GET":
        form.title.data = post.title
        form.content.data = post.content
        form.location.data = post.location
        form.event_date.data = post.event_date
        form.start_time.data = post.start_time
        form.end_time.data = post.end_time
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

    if post.date_posted:
        utc_time = pytz.utc.localize(post.date_posted)
        post.local_date_posted_value = utc_time.astimezone(MALAYSIA_TZ)
    else:
        post.local_date_posted_value = None

    join_activities = JoinActivity.query.filter_by(post_id=post.post_id).all()

    owner_conversations = []
    if current_user.is_authenticated and current_user.email.lower() == post.email.lower():
        partners = db.session.query(ChatMessage.sender_email).filter_by(post_id=post.post_id).distinct()
        for (email,) in partners:
            if email.lower() != post.email.lower():
                user = User.query.get(email)
                owner_conversations.append({"email": email, "name":user.name if user else email})

    return render_template("post_detail.html", post=post, join_activities=join_activities, owner_conversations=owner_conversations)

#Chat feature
def conversation_key(a_email: str, b_email: str) -> str:
    return "|".join(sorted([a_email.lower(), b_email.lower()]))

@app.route("/chat/<int:post_id>/<partner_email>")
def chat_with_user(post_id, partner_email):
    post = Posts.query.get_or_404(post_id)
    owner_email = post.email.lower()
    current_email = current_user.email.lower()
    partner_email = partner_email.lower()

    if current_email != owner_email and partner_email != owner_email:
        return redirect(url_for("chat_with_user", post_id=post_id, partner_email=owner_email))

    conv = conversation_key(current_email, partner_email)
    room = f"post-{post_id}-{conv}"

    messages = (ChatMessage.query.filter_by(post_id=post_id, conversation=conv).order_by(asc(ChatMessage.created_at)).all())

    partner_user = User.query.get(partner_email)
    partner_name = partner_user.name if partner_user else partner_email

    if current_email == owner_email:
        header_name = partner_name
    else:
        header_name = post.user.name

    return render_template("chat.html",post=post, room=room, username=current_user.name,header_name=header_name, 
                           messages=messages, post_id=post_id, partner_email=partner_email)

@socketio.on("join")
def on_join(data):
    room = data.get("room")
    if room:
        print("JOIN ->", current_user.email, "to", room)
    join_room(room)
    send(f"{current_user.name} joined the chat.", to=room)

@socketio.on("send_message")
def on_send_message(data):
    room = (data or {}).get("room")
    text = ((data or {}).get("message") or "").strip()
    post_id = (data or {}).get("post_id")
    partner = ((data or {}).get("partner_email")or "").lower().strip()

    if not (room and text and post_id and partner):
        return

    current_email = current_user.email.lower()
    conv = conversation_key(current_email,partner)

    msg = ChatMessage(post_id=int(post_id), conversation=conv, sender_email=current_user.email, sender_name=current_user.name, text=text)
    db.session.add(msg)
    db.session.commit()

    send({"user": msg.sender_name, "text": msg.text}, to=room)

# Notifications
@app.route("/notifications")
def notifications():
    return render_template("notifications.html")

#My profile
@app.route("/profile")
@login_required
def profile():
    recent_posts = (
        Posts.query.filter_by(email=current_user.email)
        .order_by(Posts.date_posted.desc())
        .all()
    )

    for post in recent_posts:
        if post.date_posted:
            utc_time = pytz.utc.localize(post.date_posted)
            post.local_date_posted_value = utc_time.astimezone(MALAYSIA_TZ)
        else:
            post.local_date_posted_value = None

    image_url = url_for(
        "static",
        filename=f"profile_pics/{current_user.image_file or 'default.png'}"
    )

    return render_template(
        "profile.html", 
        user=current_user, 
        image_url=image_url, 
        recent_posts=recent_posts
    )

@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def profile_edit():
    form = UpdateProfileForm()

    if form.validate_on_submit():
        current_user.name = form.name.data   
        current_user.gender = form.gender.data
        current_user.bio = form.bio.data or None

        if form.picture.data:
            filename = save_picture(form.picture.data)
            current_user.image_file = filename

        db.session.commit()
        flash("Profile updated.", "success")
        return redirect(url_for("profile"))
    
    if request.method == "GET":
        form.name.data = current_user.name  
        form.gender.data = current_user.gender
        form.bio.data = current_user.bio

    image_url = url_for(
        "static", 
        filename=f"profile_pics/{current_user.image_file or 'default.png'}"
    )

    return render_template("edit_profile.html", form=form, image_url=image_url)


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext.lower()
    picture_path = os.path.join(app.root_path, "static/profile_pics", picture_fn)

    try:
        img = Image.open(form_picture)
        img.thumbnail((256, 256))

        if f_ext.lower() in [".jpg", ".png"]:
            img.save(picture_path, optimize=True)
        else:
            img.save(picture_path, optimize=True)
    except Exception as e:
        raise ValueError("Invalid image file") from e
    
    return picture_fn

# Join Activity
@app.route("/activityrequest/<int:post_id>", methods=["POST"])
@login_required
def activityrequest(post_id):
    post = Posts.query.get_or_404(post_id)

    if post.post_status == "closed":
        flash("This activity is already closed.")
        return redirect(url_for("post_detail", post_id=post.post_id))

    # Prevent duplicate request
    existing = JoinActivity.query.filter_by(email=current_user.email, post_id=post.post_id).first()
    if existing:
        flash("You already requested this activity. Please wait for the post owner to approve")
    else:
        join_act = JoinActivity(email=current_user.email, post_id=post.post_id)
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

    # Only user posted can handle
    if post.email != current_user.email:
        flash("You are not authorized to manage this request.")
        return redirect(url_for("post_detail", post_id=post.post_id))

    if post.post_status == "closed":
        flash("This activity is already closed.")
        return redirect(url_for("post_detail", post_id=post.post_id))

    if decision == "accept":
        accepted_count = JoinActivity.query.filter_by(post_id=post.post_id, status="accepted").count()

        if accepted_count < post.participants:
            join_activity.status = "accepted"
            flash(f"{join_activity.user.name} has been accepted!")

            accepted_count += 1
            if accepted_count >= post.participants:
                post.post_status = "closed"
                flash("The activity is now full and closed.")
        else:
            flash("This activity already has enough participants.")

    elif decision == "reject":
        join_activity.status = "rejected"
        flash(f"{join_activity.user.name} has been rejected.")

    db.session.commit()
    return redirect(url_for("post_detail", post_id=post.post_id))


#admin interface
# Create default first admin
def create_first_admin():
    existing_admin = User.query.filter(User.role.in_(["admin", "both"])).first()
    
    if not existing_admin:
        admin_user = User(
            email="eewen@gmail.com",
            name="Lee Ee Wen",
            password=generate_password_hash("aaaa", method="pbkdf2:sha256"),
            gender="Female",
            sport_level="Advanced",
            security_question="book",  #  key from the question dict
            security_answer="Cinderella",
            role="both"
        )
        db.session.add(admin_user)
        db.session.commit()


# REQUEST ADMIN ACCESS
@app.route("/request_admin", methods=["GET", "POST"])
def request_admin():
    email = request.form.get("email", "").strip().lower()

    # Prevent existing admins from submitting requests
    existing_user = User.query.filter_by(email=email).first()
    if existing_user and existing_user.role in ["admin", "both"]:
        flash("You are already an admin. Please log in.")
        return redirect(url_for("login"))

    step = request.form.get("step", "email")

    if step == "email" and request.method == "POST":
        return render_template("request_admin.html", email=email, existing_user=existing_user)

    elif step == "submit" and request.method == "POST":
        join_reason = request.form.get("join_reason", "").strip()

        # Check if a request already exists
        existing_request = AdminRequest.query.filter_by(email=email).first()
        if existing_request:
            flash("One submission per email. You have already submitted a request.")
            return redirect(url_for("request_admin"))

        if existing_user:
            # Existing user: take info from User table
            password_hash = existing_user.password
            name = existing_user.name
            sec_question = existing_user.security_question
            sec_answer = existing_user.security_answer
            join_reason = request.form.get("join_reason", "").strip()
        else:
            # New user must provide all info
            name = request.form.get("name", "").strip()
            password = request.form.get("password", "").strip()
            sec_question = request.form.get("security_question", "").strip()
            sec_answer = request.form.get("security_answer", "").strip()

            if not all([name, password, sec_question, sec_answer]):
                flash("All fields are required for new users.")
                return redirect(url_for("request_admin"))

            password_hash = generate_password_hash(password, method="pbkdf2:sha256")

        # Create admin request
        new_request = AdminRequest(
            email=email,
            name=name,
            password=password_hash,
            join_reason=join_reason,
            approval="pending",
            security_question=sec_question,
            security_answer=sec_answer
        )

        db.session.add(new_request)
        db.session.commit()
        flash("Your admin request has been submitted.")
        return redirect(url_for("request_admin"))

    return render_template("request_admin.html")

        
# HANDLE REQUEST (any logged-in admin can approve/reject)
# HANDLE REQUEST (any logged-in admin can approve/reject)
@app.route("/handle-request/<int:approval_id>", methods=["GET", "POST"])
@login_required
def handle_request_admin(approval_id):
    if current_user.role not in ["admin", "both"]:
        flash("You do not have permission to perform this action.")
        return redirect(url_for("home"))

    join_request = AdminRequest.query.get_or_404(approval_id)

    if request.method == "POST":
        decision = request.form.get("decision")

        if decision == "accept":
            # Check if user already exists
            user = User.query.filter_by(email=join_request.email).first()

            if user:
                # Existing user: only update role
                if user.role == "user":
                    user.role = "admin"
                elif user.role == "admin":
                    user.role = "both"

                # Ensure security question and answer exist
                if not user.security_question or not user.security_answer:
                    user.security_question = join_request.security_question
                    user.security_answer = join_request.security_answer

            else:
                # New user: take all info from the request
                new_user = User(
                    email=join_request.email,
                    name=join_request.name,
                    password=join_request.password,  
                    role="admin",
                    gender="Other",
                    sport_level="None",
                    security_question=join_request.security_question,
                    security_answer=join_request.security_answer
                )
                db.session.add(new_user)

            join_request.approval = "approved"
            db.session.commit()
            flash(f"{join_request.name} has been approved as admin.")

        elif decision == "reject":
            join_request.approval = "rejected"
            db.session.commit()
            flash(f"Request from {join_request.name} has been rejected.")

        return redirect(url_for("admin_approval"))

    return render_template("join_admin.html", request=join_request)


# ADMIN APPROVAL PAGE
@app.route("/admin_approval")
@login_required
def admin_approval():
    # check role
    if current_user.role not in ["admin", "both"]:
        flash("You do not have permission to access this page.")
        return redirect(url_for("home"))

    # normal admin logic
    pending_requests = AdminRequest.query.filter_by(approval="pending").all()
    approved_requests = AdminRequest.query.filter_by(approval="approved").all()
    rejected_requests = AdminRequest.query.filter_by(approval="rejected").all()

    return render_template(
        "admin_approval.html",
        pending_requests=pending_requests,
        approved_requests=approved_requests,
        rejected_requests=rejected_requests
    )


@app.route("/check_approval", methods=["GET", "POST"])
def check_approval():
    email = request.form.get("email", "").strip().lower()
    open_approval_modal = True
    approval_status = None

    if request.method == "POST" and email:
        # Check if there is a pending or approved request
        req = AdminRequest.query.filter_by(email=email).first()
        if req:
            approval_status = req.approval.lower()
        else:
            # Check if user exists and has admin role
            user = User.query.filter_by(email=email).first()
            if user and user.role in ["admin", "both"]:
                approval_status = "approved"
            else:
                approval_status = "not_found"

        return render_template( # submit email to check validity
            "request_admin.html",
            open_approval_modal=open_approval_modal,
            approval_status=approval_status,
            submitted_email=email
        )

    return render_template( #check approval status
        "request_admin.html",
        open_approval_modal=open_approval_modal,
        approval_status=approval_status
    )

# LOGOUT
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for("home"))



# Admin dashboard
@app.route("/admin/dashboard")
@login_required
def admin_dashboard():
    if current_user.role != "admin":
        abort(403)  # only admin can access

    users = User.query.all()
    posts = Posts.query.all()

    return render_template(
        "admin_dashboard.html",
        users=users,
        posts=posts,
        is_admin=True  # flag for template
    )


# admin delete user
@app.route("/admin/delete_user/<string:email>", methods=["POST", "GET"])
@login_required
def delete_user(email):
    if current_user.role != "admin":
        abort(403)
    user = User.query.get_or_404(email)
    db.session.delete(user)
    db.session.commit()
    flash("User deleted.", "success")
    return redirect(url_for("admin_dashboard"))


# admin reports
@app.route("/admin/reports")
@login_required
def admin_reports():
    
    users = User.query.all()
    posts = Posts.query.all()
    join_requests = JoinActivity.query.all()  

    return render_template(
        "admin_reports.html",
        users=users,
        posts=posts,
        join_requests=join_requests
    )


# Upload location list
import io

@app.route("/admin/updatelocation", methods=["GET", "POST"])
@login_required
def upload_location_csv():
    if current_user.role not in ["admin", "both"]:
        flash("Request Denied. You are not admin.")
        return redirect(url_for("login"))

    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            flash("Please select a CSV file.")
            return redirect(url_for("upload_location_csv"))

        try:
            csv_path = os.path.join("instance", "locations.csv")

            # Load existing locations
            locations = {}
            if os.path.exists(csv_path):
                with open(csv_path, "r", encoding="utf-8") as f:
                    for row in csv.DictReader(f):
                        try:
                            locations[row["name"].strip()] = float(row["distance"])
                        except:
                            continue

            # Read uploaded
            reader = csv.DictReader(io.TextIOWrapper(file.stream, encoding="utf-8"))
            if not {"name", "distance"}.issubset(reader.fieldnames):
                flash("CSV must have 'name' and 'distance' columns.")
                return redirect(url_for("upload_location_csv"))

            new_or_updated = 0
            for row in reader:
                try:
                    name, dist = row["name"].strip(), float(row["distance"])
                    if name not in locations or locations[name] != dist:
                        locations[name] = dist
                        new_or_updated += 1
                except:
                    continue

            if not new_or_updated:
                flash("No new or updated locations found.")
                return redirect(url_for("upload_location_csv"))

            # Save sorted
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["name", "distance"])
                writer.writeheader()
                for n, d in sorted(locations.items(), key=lambda x: x[1]):
                    writer.writerow({"name": n, "distance": f"{d:.2f}"})

            flash(f"Upload successful! {new_or_updated} location(s) added/updated.")
        except Exception as e:
            flash(f"Error uploading CSV: {e}")

        return redirect(url_for("upload_location_csv"))

    return render_template("uploadlocation.html")
            

# Run app
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        create_first_admin()
    app.run(debug=True)