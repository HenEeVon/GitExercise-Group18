from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, current_app
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
from werkzeug.utils import secure_filename
import pytz
import os, secrets
from sqlalchemy import func, or_, asc
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
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024


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
    is_suspended = db.Column(db.Boolean, default=False)

    posts = db.relationship("Posts", back_populates="user", lazy=True)

    def get_id(self):
        return self.user_email


class Admin(db.Model):
    __tablename__ = "admins"   
    admin_email = db.Column(db.String(255), primary_key=True)
    admin_name = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)


class AdminRequest(db.Model):
    __tablename__ = "admin_requests"  

    approval_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    admin_email = db.Column(db.String(255), nullable=False)
    admin_name = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    join_reason = db.Column(db.Text, nullable=False)
    approval = db.Column(db.String(20), default="pending")  # values: pending / approved / rejected



class Posts(db.Model):
    __tablename__ = "posts"

    post_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    event_date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    post_status = db.Column(db.String(20), default="open")
    participants = db.Column(db.Integer, nullable=False)
    image_filename = db.Column(db.String(200), nullable=True)   

    # ✅ Foreign keys
    user_email = db.Column(db.String, db.ForeignKey("users.user_email"), nullable=True)
    admin_email = db.Column(db.String, db.ForeignKey("admins.admin_email"), nullable=True)

    is_hidden = db.Column(db.Boolean, default=False)

    user = db.relationship("User", backref="user_posts", lazy=True, overlaps="posts")
    admin = db.relationship("Admin", backref="admin_posts", lazy=True)
  

class Reports(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("posts.post_id"), nullable=False)
    reporter_email = db.Column(db.String(120), nullable=False)  # works for both users & admins
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    post = db.relationship("Posts", backref=db.backref("reports", lazy=True, cascade="all, delete-orphan"))


class JoinActivity(db.Model):
    __tablename__ = "join_activities"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_email = db.Column(db.String(255), db.ForeignKey("users.user_email"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("posts.post_id"), nullable=False)
    status = db.Column(db.String(20), default="pending")  # pending / accepted / rejected

    user = db.relationship("User", backref="join_activities", lazy=True)
    post = db.relationship("Posts", backref="join_activities", lazy=True)

def load_locations():
    csv_path = os.path.join("instance", "locations.csv")
    choices = []
    
    if not os.path.exists(csv_path):
        # Return default choices if file doesn't exist
        return [("https://maps.app.goo.gl/BVDJU9KfrB7Q43oz9", "Default Location")]
    
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            csv_reader = csv.DictReader(f, delimiter='\t')
            for row in csv_reader:
                choices.append((row["google_maps_url"], row["name"]))
    except Exception as e:
        print(f"Error loading locations: {e}")
        choices = [("https://maps.app.goo.gl/BVDJU9KfrB7Q43oz9", "Error Loading Locations")]
    
    return choices
    
# Activity Form database
class ActivityForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    image = FileField("Upload Image", validators=[FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Images only!')])
    content = TextAreaField("Content", validators=[DataRequired()])
    location = StringField("Location", validators=[DataRequired()])
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
        
        if user.is_suspended:
            flash("Your account has been suspended. Contact admin for support.", "danger")
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



@app.route("/index")
def posts():
    # Default: show only non-hidden posts
    posts = Posts.query.filter_by(is_hidden=False).order_by(Posts.date_posted.desc()).all()

    # Convert UTC → Malaysia timezone
    for post in posts:
        if post.date_posted:
            utc_time = pytz.utc.localize(post.date_posted)
            post.local_date_posted_value = utc_time.astimezone(MALAYSIA_TZ)
        else:
            post.local_date_posted_value = None

    # Detect logged-in account (user or admin)
    current_admin = None
    if session.get("admin_email"):
        current_admin = Admin.query.get(session.get("admin_email"))

    return render_template(
        "index.html",
        posts=posts,
        admin=current_admin,
        user=current_user if current_user.is_authenticated else None
    )



# Search feature
@app.route("/search", methods=["GET"])
def search():
    sport = (request.args.get("sport") or "").strip().lower()
    dateinpost = (request.args.get("date") or "").strip()

    searched = False
    query = Posts.query  # don't force join with User (breaks for admin posts)

    # Filter by sport if provided
    if sport:
        searched = True
        query = query.filter(
            or_(
                func.lower(Posts.title).like(f"%{sport}%"),
                func.lower(Posts.content).like(f"%{sport}%"),
                func.lower(Posts.location).like(f"%{sport}%"),
                func.lower(Posts.user_email).like(f"%{sport}%")  # match against email
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

    # Detect if admin is logged in
    current_admin = None
    if session.get("admin_email"):
        current_admin = Admin.query.get(session.get("admin_email"))

    return render_template(
        "index.html",
        posts=results,
        searched=searched,
        sport=sport,
        date=dateinpost,
        admin=current_admin,
        user=current_user if current_user.is_authenticated else None
    )


# Error page
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404



# Create post form
@app.route("/create", methods=["GET", "POST"])
def create():
    if not current_user.is_authenticated and not session.get("admin_email"):
        flash("You need to log in first!", "danger")
        return redirect(url_for("login"))
    
    form = ActivityForm()

    if form.validate_on_submit():
        # Handle image upload
        image_file = form.image.data
        filename = None
        if image_file:
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(image_path)

        # Regular user creating post
        if current_user.is_authenticated:
            new_post = Posts(
                title=form.title.data,
                content=form.content.data,
                location=form.location.data,
                event_date=form.event_date.data,
                start_time=form.start_time.data,
                end_time=form.end_time.data,
                participants=form.participants.data,
                user_email=current_user.user_email,
                image_filename=filename  # <-- new field
            )
        # Admin creating post
        elif session.get("admin_email"):
            new_post = Posts(
                title=form.title.data,
                content=form.content.data,
                location=form.location.data,
                event_date=form.event_date.data,
                start_time=form.start_time.data,
                end_time=form.end_time.data,
                participants=form.participants.data,
                admin_email=session["admin_email"],
                image_filename=filename  # <-- new field
            )

        db.session.add(new_post)
        db.session.commit()
        flash("Post created successfully!", "success")
        return redirect(url_for("posts"))

    return render_template("create.html", form=form)


# Edit post
@app.route("/edit/<int:post_id>", methods=["GET", "POST"])
def edit_post(post_id):
    post = Posts.query.get_or_404(post_id)

    # Check if the current user is allowed to edit
    if current_user.is_authenticated:
        is_owner = (post.user_email == current_user.user_email)
    elif session.get("admin_email"):
        is_owner = (post.admin_email == session.get("admin_email"))
    else:
        is_owner = False

    if not is_owner:
        flash("You are not authorized to edit this post.", "danger")
        return redirect(url_for("posts"))

    form = ActivityForm(obj=post)

    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        post.location = form.location.data
        post.event_date = form.event_date.data
        post.start_time = form.start_time.data
        post.end_time = form.end_time.data
        post.participants = form.participants.data

        # Handle new image upload
        if form.image.data:
            # If old image exists → delete it
            if post.image_filename:
                old_path = os.path.join(current_app.root_path, "static/uploads", post.image_filename)
                if os.path.exists(old_path):
                    os.remove(old_path)

            # Save new image
            file = form.image.data
            filename = secure_filename(file.filename)
            file.save(os.path.join(current_app.root_path, "static/uploads", filename))
            post.image_filename = filename

        db.session.commit()
        flash("Post updated successfully!", "success")
        return redirect(url_for("post_detail", post_id=post.post_id))

    return render_template("edit_post.html", form=form, post=post)




# Delete post
# Delete post
@app.route("/delete/<int:post_id>", methods=["POST"])
def delete(post_id):
    if not current_user.is_authenticated and not session.get("admin_email"):
        flash("You must log in first.")
        return redirect(url_for("login"))

    post = Posts.query.get_or_404(post_id)

    # ✅ Permission check (user OR admin)
    if current_user.is_authenticated:
        is_author = (post.user_email == current_user.user_email)
    elif session.get("admin_email"):
        is_author = True   # admins can delete any post
    else:
        is_author = False

    if not is_author:
        flash("You don't have permission to delete this post.", "danger")
        return redirect(url_for("posts"))

    # ✅ Delete image file if exists
    if post.image_filename:
        img_path = os.path.join(current_app.root_path, "static/uploads", post.image_filename)
        if os.path.exists(img_path):
            os.remove(img_path)

    db.session.delete(post)
    db.session.commit()
    flash("Post deleted successfully!", "danger")

    # ✅ Redirect based on referrer
    if request.referrer and "admin/reports" in request.referrer:
        return redirect(url_for("admin_reports"))
    else:
        return redirect(url_for("posts"))


# Report post
@app.route("/report/<int:post_id>", methods=["POST"])
def report_post(post_id):
    if not current_user.is_authenticated and not session.get("admin_email"):
        flash("You must be logged in to report posts.", "danger")
        return redirect(url_for("login"))

    post = Posts.query.get_or_404(post_id)

    # determine who reported
    reporter_email = current_user.user_email if current_user.is_authenticated else session.get("admin_email")

    # prevent duplicate reports by same reporter
    existing_report = Reports.query.filter_by(post_id=post_id, reporter_email=reporter_email).first()
    if existing_report:
        flash("You already reported this post.", "warning")
        return redirect(url_for("post_detail", post_id=post_id))

    # create and commit the report
    new_report = Reports(post_id=post_id, reporter_email=reporter_email)
    db.session.add(new_report)
    db.session.commit()

    # count total reports from Reports table and hide if threshold reached
    report_count = Reports.query.filter_by(post_id=post_id).count()
    if report_count >= 3:
        post.is_hidden = True
        db.session.commit()

    flash("Post reported successfully.", "success")
    return redirect(url_for("posts"))





# Post detail
@app.route("/post/<int:post_id>")
def post_detail(post_id):
    post = Posts.query.get_or_404(post_id)

    # Get query params with defaults
    readonly = request.args.get("readonly", type=int)
    from_reports = request.args.get("from_reports", default=0, type=int)
    from_dashboard = request.args.get("from_dashboard", default=0, type=int)

    # 🔑 Force readonly for admins on first visit, while preserving origin flags
    if session.get("admin_email") and readonly is None:
        args = request.args.to_dict(flat=True)  # copy all current args
        args["readonly"] = 1                   # enforce readonly
        # If no source flag is set, keep it consistent
        args.setdefault("from_reports", from_reports)
        args.setdefault("from_dashboard", from_dashboard)
        return redirect(url_for("post_detail", post_id=post_id, **args))

    # Date handling
    if post.date_posted:
        utc_time = pytz.utc.localize(post.date_posted)
        post.local_date_posted_value = utc_time.astimezone(MALAYSIA_TZ)
    else:
        post.local_date_posted_value = None

    join_activities = JoinActivity.query.filter_by(post_id=post.post_id).all()

    owner_conversations = []
    owner_email = post.user_email or post.admin_email  

    if current_user.is_authenticated and current_user.user_email and owner_email:
        if current_user.user_email.lower() == owner_email.lower():
            partners = (
                db.session.query(ChatMessage.sender_email)
                .filter_by(post_id=post.post_id)
                .distinct()
            )
            for (email,) in partners:
                if email.lower() != owner_email.lower():
                    user = User.query.get(email)
                    owner_conversations.append(
                        {"email": email, "name": user.user_name if user else email}
                    )

    return render_template(
        "post_detail.html",
        post=post,
        join_activities=join_activities,
        owner_conversations=owner_conversations,
        readonly=readonly,
        from_reports=from_reports,
        from_dashboard=from_dashboard
    )




def conversation_key(a_email: str, b_email: str) -> str:
    return "|".join(sorted([a_email.lower(), b_email.lower()]))

@app.route("/chat/<int:post_id>/<partner_email>")
def chat_with_user(post_id, partner_email):
    post = Posts.query.get_or_404(post_id)
    owner_email = post.user_email.lower()

    # Determine who is logged in (user OR admin)
    if current_user.is_authenticated:
        current_email = current_user.user_email.lower()
        current_name = current_user.user_name
    elif session.get("admin_email"):
        current_email = session.get("admin_email").lower()
        admin_obj = Admin.query.get(session.get("admin_email"))
        current_name = admin_obj.admin_name if admin_obj else "Admin"
    else:
        flash("You must log in to chat.")
        return redirect(url_for("login"))

    partner_email = partner_email.lower()

    # Prevent outsiders from chatting
    if current_email != owner_email and partner_email != owner_email:
        return redirect(url_for("chat_with_user", post_id=post_id, partner_email=owner_email))

    conv = conversation_key(current_email, partner_email)
    room = f"post-{post_id}-{conv}"

    messages = (
        ChatMessage.query.filter_by(post_id=post_id, conversation=conv)
        .order_by(asc(ChatMessage.created_at))
        .all()
    )

    # Partner display name
    partner_user = User.query.get(partner_email)
    partner_name = partner_user.user_name if partner_user else partner_email

    # Show correct chat header
    header_name = partner_name if current_email == owner_email else post.user.user_name

    return render_template(
        "chat.html",
        post=post,
        room=room,
        username=current_name,
        header_name=header_name,
        messages=messages,
        post_id=post_id,
        partner_email=partner_email,
    )

@socketio.on("join")
def on_join(data):
    room = data.get("room")

    # Identify sender
    if current_user.is_authenticated:
        name = current_user.user_name
        email = current_user.user_email
    elif session.get("admin_email"):
        email = session.get("admin_email")
        admin_obj = Admin.query.get(email)
        name = admin_obj.admin_name if admin_obj else "Admin"
    else:
        return  # No one logged in, ignore

    if room:
        print("JOIN ->", email, "to", room)
        join_room(room)
        send(f"{name} joined the chat.", to=room)

@socketio.on("send_message")
def on_send_message(data):
    room = (data or {}).get("room")
    text = ((data or {}).get("message") or "").strip()
    post_id = (data or {}).get("post_id")
    partner = ((data or {}).get("partner_email") or "").lower().strip()

    if not (room and text and post_id and partner):
        return

    # Identify sender (user OR admin)
    if current_user.is_authenticated:
        current_email = current_user.user_email.lower()
        current_name = current_user.user_name
    elif session.get("admin_email"):
        current_email = session.get("admin_email").lower()
        admin_obj = Admin.query.get(session.get("admin_email"))
        current_name = admin_obj.admin_name if admin_obj else "Admin"
    else:
        return  # No sender, ignore

    conv = conversation_key(current_email, partner)

    msg = ChatMessage(
        post_id=int(post_id),
        conversation=conv,
        sender_email=current_email,
        sender_name=current_name,
        text=text,
    )
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
def activityrequest(post_id):
    post = Posts.query.get_or_404(post_id)

    if post.post_status == "closed":
        flash("This activity is already closed.")
        return redirect(url_for("post_detail", post_id=post.post_id))

    # Determine if user OR admin is logged in
    if current_user.is_authenticated:
        requester_email = current_user.user_email
        requester_name = current_user.user_name
    elif session.get("admin_email"):
        requester_email = session.get("admin_email")
        admin_obj = Admin.query.get(requester_email)
        requester_name = admin_obj.admin_name if admin_obj else "Admin"
    else:
        flash("You must log in first.")
        return redirect(url_for("login"))

    # Prevent duplicate request
    existing = JoinActivity.query.filter_by(user_email=requester_email, post_id=post.post_id).first()
    if existing:
        flash("You already requested this activity. Please wait for the post owner to approve.")
    else:
        join_act = JoinActivity(user_email=requester_email, post_id=post.post_id)
        db.session.add(join_act)
        db.session.commit()
        flash(f"Your request has been sent to the post owner ({requester_name}).")

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
            return redirect(url_for("admin_dashboard"))
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
        existing = AdminRequest.query.filter_by(admin_email=email, approval="pending").first()
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


# HANDLE REQUEST (any logged-in admin can approve/reject)
@app.route("/handle-admin-request/<int:approval_id>", methods=["GET", "POST"])
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
                    password=join_request.password,  # already hashed
                )
                db.session.add(new_admin)

            db.session.delete(join_request)
            db.session.commit()
            flash(f"{join_request.admin_name} has been approved as admin.")

        elif decision == "reject":
            db.session.delete(join_request)
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

    requests = AdminRequest.query.filter_by(approval="pending").all()

    return render_template("admin_approval.html", admin=current_admin, requests=requests)

# LOGOUT
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for("home"))



# Admin dashboard
@app.route("/admin/dashboard")
def admin_dashboard():
    # Check if admin is logged in via session
    email = session.get("admin_email")
    if not email:
        flash("You must log in first.")
        return redirect(url_for("login_admin"))

    current_admin = Admin.query.get(email)
    if not current_admin:
        session.clear()
        flash("Session expired. Please log in again.")
        return redirect(url_for("login_admin"))

    # Now fetch dashboard data
    users = User.query.all()
    posts = Posts.query.all()
    join_requests = JoinActivity.query.all()

    return render_template(
        "admin_dashboard.html",
        admin=current_admin,
        users=users,
        posts=posts,
        join_requests=join_requests
    )



# Admin delete user
@app.route("/admin/delete_user/<string:user_email>", methods=["POST", "GET"])
def delete_user(user_email):
    # Check if admin is logged in via session
    email = session.get("admin_email")
    if not email:
        flash("You must log in first.")
        return redirect(url_for("login_admin"))

    current_admin = Admin.query.get(email)
    if not current_admin:
        session.clear()
        flash("Session expired. Please log in again.")
        return redirect(url_for("login_admin"))

    user = User.query.get_or_404(user_email)
    db.session.delete(user)
    db.session.commit()
    flash("User deleted.", "success")
    return redirect(url_for("admin_dashboard"))



# Admin reports
@app.route("/admin/reports")
def admin_reports():
    if not session.get("admin_email"):
        flash("Admins only!", "danger")
        return redirect(url_for("login"))

    flagged_posts = (
        db.session.query(Posts, db.func.count(Reports.id).label("report_count"))
        .join(Reports, Reports.post_id == Posts.post_id)
        .group_by(Posts.post_id)
        .having(db.func.count(Reports.id) >= 3)  # flag threshold
        .all()
    )

    suspended_users = User.query.filter_by(is_suspended=True).all()

    return render_template("admin_reports.html", flagged_posts=flagged_posts, suspended_users=suspended_users)

# Suspend user
@app.route("/suspend/<string:user_email>", methods=["POST"])
def suspend_user(user_email):
    if not session.get("admin_email"):  # only admins allowed
        flash("Unauthorized access", "danger")
        return redirect(url_for("login"))

    user = User.query.filter_by(user_email=user_email).first_or_404()
    user.is_suspended = True
    db.session.commit()

    flash(f"User {user.user_email} has been suspended.", "warning")
    return redirect(url_for("admin_reports"))

# Unsuspend user
@app.route("/unsuspend/<string:user_email>", methods=["POST"])
def unsuspend_user(user_email):
    if not session.get("admin_email"):
        flash("Unauthorized access", "danger")
        return redirect(url_for("login"))

    user = User.query.filter_by(user_email=user_email).first_or_404()
    user.is_suspended = False
    db.session.commit()

    flash(f"User {user.user_email} has been unsuspended.", "success")
    return redirect(url_for("admin_dashboard"))

# Reactivate hidden post
@app.route("/reactivate/<int:post_id>", methods=["POST"])
def reactivate_post(post_id):
    if not session.get("admin_email"):
        flash("Unauthorized access", "danger")
        return redirect(url_for("login"))

    post = Posts.query.get_or_404(post_id)
    post.is_hidden = False

    # delete all reports for this post
    Reports.query.filter_by(post_id=post_id).delete()

    db.session.commit()

    flash("Post has been reactivated and is now visible.", "success")
    return redirect(url_for("admin_reports"))


@app.context_processor
def inject_admin():
    email = session.get("admin_email")
    if email:
        current_admin = Admin.query.get(email)
        return dict(admin=current_admin)
    return dict(admin=None)


# Run app
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        create_first_admin()
    app.run(debug=True)