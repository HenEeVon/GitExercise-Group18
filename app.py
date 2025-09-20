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
    user_email = db.Column(db.String(255), primary_key=True)
    user_name = db.Column(db.String(255), nullable=False)
    gender = db.Column(db.String(50), nullable=False)
    sport_level = db.Column(db.String(255), nullable=False)
    security_question = db.Column(db.String(255), nullable=False)
    security_answer = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    image_file = db.Column(db.String(255), nullable=True, default="default.png")
    bio = db.Column(db.Text, nullable=True)
    role = db.Column(db.String(20), default="user") 
    

    def get_id(self):
        return self.user_email

class Admin(db.Model):
    __tablename__ = "admin"
    admin_email =  db.Column(db.String(255), primary_key=True)
    admin_name = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)

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

    event_date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)

    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    post_status = db.Column(db.String(20), default="open")
    participants = db.Column(db.Integer, nullable=False, default=1)

    user_email = db.Column(db.String(255), db.ForeignKey("users.user_email"), nullable=False)
    user = db.relationship("User", backref="posts")



class JoinActivity(db.Model):
    __tablename__ = "join_activities"
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(255), db.ForeignKey("users.user_email"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("posts.post_id"), nullable=False)
    status = db.Column(db.String(20), default="pending")  # pending / accepted / rejected

    user = db.relationship("User", backref="join_activities")
    post = db.relationship("Posts", backref="join_activities")

def load_locations():
    import csv, os
    csv_path = os.path.join("instance", "locations.csv")
    choices = []

    if not os.path.exists(csv_path):
        return [("none", "--Please select a location--")]

    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            csv_reader = csv.DictReader(f)
            for row in csv_reader:
                name = (row.get("name") or "").strip()
                if name:
                    # Value is just the name now
                    choices.append((name, name))
    except Exception as e:
        print(f"Error loading locations: {e}")
        choices = [("none", "Error Loading Locations")]

    if not choices:
        choices = [("none", "--Please select a location--")]

    return choices

    
# Activity Form database
class ActivityForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    content = TextAreaField("Content", validators=[DataRequired()])
    location = SelectField("Location", choices=[])

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
    user_name = StringField("Full Name", validators=[DataRequired(), Length(min=2, max=50)])
    gender = SelectField("Gender", choices=[("Male", "Male"), ("Female", "Female"), ("Other", "Other")])
    bio = TextAreaField("Bio", validators=[Length(max=200)])
    picture = FileField("Update Profile Picture", validators=[FileAllowed(["jpg", "png"])])
    submit = SubmitField("Update")


# User loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(user_email=user_id).first()

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

# Register page
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        user_email = request.form["user_email"].strip().lower()
        user_name = request.form["user_name"]
        gender = request.form["gender"]
        sport_level = request.form["sport_level"]
        security_question = request.form["security_question"]
        security_answer = request.form["security_answer"].strip().lower()
        password = request.form["password"]
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

        new_user = User(user_email=user_email, user_name=user_name, gender=gender, sport_level=sport_level, security_question=security_question, security_answer=security_answer, password=hashed_password)

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
        email = request.form.get("user_email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Please enter email and password.")
            return redirect(url_for("login"))

        user = User.query.filter_by(user_email=email).first()
        if not user:
            flash("Invalid email !")
            return redirect(url_for("login"))
        
        if check_password_hash(user.password, password):
            login_user(user)
            flash(f"Welcome {user.user_name}!")
            return redirect(url_for("posts"))
        else:
            flash("Wrong password. Please type again.")
            return redirect(url_for("login"))
        
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

@app.route("/resetpass", methods=["GET", "POST"])
def resetpass():
    user_email = None
    security_question = None

    if request.method == "POST":
        step = request.form.get("current")
        # check email validity
        if step == "email":
            user_email = request.form.get("user_email", "").strip().lower()
            if not user_email:
                flash("Please enter your email.")
                return render_template("login.html", open_reset_modal=True)

            user = User.query.filter_by(user_email=user_email).first()
            if not user:
                flash("Email not found.")
                return render_template("login.html", open_reset_modal=True)

            # Map security question ket to get the sentence
            security_question = question.get(user.security_question, "Security question not found")
            return render_template(
                "login.html",
                open_reset_modal=True,
                user_email=user_email,
                security_question=security_question
            )

        # answer security answers so can reset password
        elif step == "reset":
            user_email = request.form.get("user_email", "").strip().lower()
            answer = request.form.get("security_answer", "").strip().lower()
            new_password = request.form.get("new_password", "")

            if not user_email or not answer or not new_password:
                flash("Please fill all fields.")
                return render_template("login.html", open_reset_modal=True)

            user = User.query.filter_by(user_email=user_email).first()
            if not user:
                flash("Email not found.")
                return render_template("login.html", open_reset_modal=True)

            if user.security_answer.lower() == answer:
                # Update password
                user.password = generate_password_hash(new_password, method="pbkdf2:sha256")
                db.session.commit()
                flash("Password updated successfully! Please log in.")
                return redirect(url_for("login"))
            else:
                flash("Security answer incorrect.")
                return render_template(
                    "login.html",
                    open_reset_modal=True,
                    user_email=user_email,
                    security_question=question.get(user.security_question, "Security question not found")
                )

    return render_template("login.html", open_reset_modal=True)



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
    query = Posts.query.join(User)

    # Filter by sport if provided
    if sport:
        searched = True
        query = query.filter(
            or_(
                func.lower(Posts.title).like(f"%{sport}%"),
                func.lower(Posts.content).like(f"%{sport}%"),
                func.lower(Posts.location).like(f"%{sport}%"),
                func.lower(User.user_name).like(f"%{sport}%")
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
# Create post form with debug
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
                user_email=current_user.user_email,
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

#My profile
@app.route("/profile")
@login_required
def profile():
    recent_posts = (
        Posts.query.filter_by(user_email=current_user.user_email)
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
        current_user.user_name = form.user_name.data   
        current_user.gender = form.gender.data
        current_user.bio = form.bio.data or None

        if form.picture.data:
            filename = save_picture(form.picture.data)
            current_user.image_file = filename

        db.session.commit()
        flash("Profile updated.", "success")
        return redirect(url_for("profile"))
    
    if request.method == "GET":
        form.user_name.data = current_user.user_name  
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
# Create default first admin
def create_first_admin():
    if not Admin.query.first():
        admin = Admin(
            admin_email="eewen@gmail.com".lower(),
            admin_name="Lee Ee Wen",
            password=generate_password_hash("aaaa", method="pbkdf2:sha256"),
        )
        db.session.add(admin)
        db.session.commit()


# LOGIN ADMIN
@app.route("/login_admin", methods=["GET", "POST"])
def login_admin():
    if request.method == "POST":
        email = request.form["admin_email"].strip().lower()
        password = request.form["password"]

        admin_instance = Admin.query.get(email)
        if not admin_instance:
            flash("No admin found with this email.")
            return redirect(url_for("login_admin"))

        if check_password_hash(admin_instance.password, password):
            session["admin_email"] = admin_instance.admin_email
            flash(f"Welcome {admin_instance.admin_name}!")
            return redirect(url_for("admin_approval"))
        else:
            flash("Password incorrect.")

    return render_template("login_admin.html")


# REQUEST ADMIN ACCESS
@app.route("/request_admin", methods=["GET", "POST"])
def request_admin():
    if request.method == "POST":
        email = request.form.get("admin_email", "").strip().lower()
        admin_name = request.form.get("admin_name", "")
        password = request.form.get("password", "")
        join_reason = request.form.get("join_reason", "")

        # already an admin?
        if Admin.query.get(email):
            flash("You are already an admin. Please log in instead.")
            return redirect(url_for("login_admin"))

        # already requested?
        existing = AdminRequest.query.filter_by(admin_email=email).first()
        if existing:
            flash("User can only request once, You already submitted a request before.")
            return redirect(url_for("login_admin"))

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

        return redirect(url_for("request_admin"))

    return render_template("request_admin.html")


# HANDLE REQUEST (any logged-in admin can approve/reject)
@app.route("/handle-request/<int:approval_id>", methods=["GET", "POST"])
def handle_request_admin(approval_id):
    if "admin_email" not in session:
        flash("You must log in first.")
        return redirect(url_for("login_admin"))

    current_admin = Admin.query.get(session["admin_email"])
    if not current_admin:
        flash("Invalid session. Please log in again.")
        return redirect(url_for("login_admin"))

    join_request = AdminRequest.query.get_or_404(approval_id)

    if request.method == "POST":
        decision = request.form.get("decision")

        if decision == "accept":
            if not Admin.query.get(join_request.admin_email):
                new_admin = Admin(
                    admin_email=join_request.admin_email.lower(),
                    admin_name=join_request.admin_name,
                    password=join_request.password,
                )
                db.session.add(new_admin)
            join_request.approval = "approved"  
            db.session.commit()
            flash(f"{join_request.admin_name} has been approved as admin.")

        elif decision == "reject":
            join_request.approval = "rejected" 
            db.session.commit()
            flash(f"Request from {join_request.admin_name} has been rejected.")

        return redirect(url_for("admin_approval"))

    return render_template("join_admin.html", request=join_request)

# ADMIN APPROVAL PAGE
@app.route("/admin_approval")
def admin_approval():
    email = session.get("admin_email")
    if not email:
        flash("You must log in first.")
        return redirect(url_for("login_admin"))

    current_admin = Admin.query.get(email)
    if not current_admin:
        session.clear()
        flash("Session expired. Please log in again.")
        return redirect(url_for("login_admin"))

    pending_requests = AdminRequest.query.filter_by(approval="pending").order_by(AdminRequest.approval_id.desc()).all()
    approved_requests = AdminRequest.query.filter_by(approval="approved").order_by(AdminRequest.approval_id.desc()).all()
    rejected_requests = AdminRequest.query.filter_by(approval="rejected").order_by(AdminRequest.approval_id.desc()).all()

    return render_template(
        "admin_approval.html",
        admin=current_admin,
        pending_requests=pending_requests,
        approved_requests=approved_requests,
        rejected_requests=rejected_requests
    )

@app.route("/check_approval", methods=["GET", "POST"])
def check_approval():
    admin_email = request.form.get("admin_email", "").strip().lower()
    open_approval_modal = True
    approval_status = None

    if request.method == "POST" and admin_email:
        req = AdminRequest.query.filter_by(admin_email=admin_email).first()
        if req:
            approval_status = req.approval.lower()
        else:
            if Admin.query.get(admin_email):
                approval_status = "approved"
            else:
                approval_status = "not_found"

        return render_template(  #submit and check email exist or not
            "request_admin.html",
            open_approval_modal=open_approval_modal,
            approval_status=approval_status,
            submitted_email=admin_email
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

    users = User.query.all()
    posts = Posts.query.all()
    join_requests = JoinActivity.query.all()

    return render_template(
        "admin_dashboard.html",
        users=users,
        posts=posts,
        join_requests=join_requests
    )


# admin promote user
@app.route("/admin/promote_user/<string:user_email>", methods=["POST"])
@login_required
def promote_user(user_email):
    if current_user.role != "admin":
        abort(403)

    user = User.query.get_or_404(user_email)
    user.role = "admin"  # promote to admin
    db.session.commit()
    flash(f"{user.user_name} has been promoted to admin.", "success")
    return redirect(url_for("admin_dashboard"))



# admin delete user
@app.route("/admin/delete_user/<string:user_email>", methods=["POST", "GET"])
@login_required
def delete_user(user_email):
    if current_user.role != "admin":
        abort(403)
    user = User.query.get_or_404(user_email)
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

# Run app
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        create_first_admin()
    app.run(debug=True)