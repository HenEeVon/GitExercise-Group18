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
from werkzeug.utils import secure_filename
from sqlalchemy.exc import IntegrityError
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, IntegerField, DateField, TimeField,  SelectField, RadioField
from wtforms.validators import DataRequired, NumberRange, Length, Optional, ValidationError
from flask_wtf.file import FileField, FileAllowed
from datetime import date, datetime
from PIL import Image
from werkzeug.utils import secure_filename
import pytz
import os, secrets
from sqlalchemy import func, or_, asc, case
import csv 
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
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 *1024

@app.context_processor
def notif_count():
    if current_user.is_authenticated:
        count = Notification.query.filter_by(email=current_user.email, is_read=False).count()
        return {"unread_count": count}
    return {"unread_count": 0}


Security_Questions = [
    ("pet","What was your first pet name?"),
    ("car","What was your first car?"),
    ("hospital","What hospital name were you born in?"),
    ("city", "What city were you born in?"),
    ("girlfriend", "What was your first ex girlfriend's name?"),
    ("boyfriend", "What was your first ex boyfriend's name?"),
    ("school", "What was the name of your first school?"),
    ("book", "What was your favorite childhood book?")
]

# User database
class User(db.Model, UserMixin):
    __tablename__ = "users"
    email = db.Column(db.String(255), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    sport_level = db.Column(db.String(50), nullable=False)
    security_question = db.Column(db.String(255), nullable=False)
    security_answer = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    image_file = db.Column(db.String(255), nullable=False, default="default_image.png")
    bio = db.Column(db.Text, default="This user has not added a bio yet.", nullable=False)
    role = db.Column(db.String(20), default="user") 
    is_suspended = db.Column(db.Boolean, default=False)
    posts = db.relationship("Posts", back_populates="user", lazy=True, cascade="all, delete-orphan")

    def get_id(self):
        return self.email

class Admin(db.Model):
    __tablename__ = "admins"   

    email = db.Column(db.String(255), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)


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

    # FK to user
    email = db.Column(db.String(255), db.ForeignKey("users.email"), nullable=False)
    user = db.relationship("User", back_populates="posts")

    is_hidden = db.Column(db.Boolean, default=False)


class Reports(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("posts.post_id"), nullable=False)
    reporter_email = db.Column(db.String(255), nullable=False)  # works for both users & admins
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    post = db.relationship(
        "Posts",
        backref=db.backref("reports", lazy=True, cascade="all, delete-orphan")
    )


class JoinActivity(db.Model):
    __tablename__ = "join_activities"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), db.ForeignKey("users.email"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("posts.post_id"), nullable=False)
    status = db.Column(db.String(20), default="pending")  # pending / accepted / rejected

    user = db.relationship("User", backref="join_activities", lazy=True)
    post = db.relationship("Posts", backref="join_activities", lazy=True)


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
                        locations.append((name, f"{name} ({distance}km)", distance))
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
    image = FileField("Upload Image", validators=[FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Images only!')])
    content = TextAreaField("Content", validators=[DataRequired()])
    location = SelectField("Location", choices=[], validators=[DataRequired()])
    event_date = DateField("Activity Date", format="%Y-%m-%d", validators=[DataRequired()])
    start_time = TimeField("Start Time", format="%H:%M", validators=[DataRequired()])
    end_time = TimeField("End Time", format="%H:%M", validators=[DataRequired()])
    participants = IntegerField("Required Participants", validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField("Post")

    def validate_event_date(form, field):
        if field.data < date.today():
            raise ValidationError("Event date must be today or in the future.")

    def validate_end_time(form, field):
        if form.start_time.data and field.data <= form.start_time.data:
            raise ValidationError("End time must be after start time.")


# Chat database
class ChatMessage(db.Model):
    __tablename__ = "chat_messages"

    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, nullable=False, index=True)
    conversation = db.Column(db.String(600), nullable=False, index=True)

    sender_email = db.Column(db.String(255), nullable=False)  # unified with email convention
    sender_name = db.Column(db.String(255), nullable=False)
    text = db.Column(db.Text, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

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

#Update Profile database
class UpdateProfileForm(FlaskForm):
    name = StringField("Full Name", validators=[DataRequired(), Length(min=2, max=50)])
    gender = SelectField("Gender", choices=[("Male", "Male"), ("Female", "Female")])
    sport_level = SelectField("Fitness Level", choices=[("newbie","Newbie"),("intermediate","Intermediate"),("advanced","Advanced")], validators=[DataRequired()])
    bio = TextAreaField("Bio", validators=[Length(max=200)])
    security_question = SelectField("Security Question", choices=question, validators=[DataRequired()])
    security_answer = StringField("Security Answer", validators=[DataRequired(), Length(max=255)])
    picture = FileField("Update Profile Picture", validators=[FileAllowed(["jpg", "png"])])
    submit = SubmitField("Update")


# Notification database
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), db.ForeignKey("users.email"), nullable=False)
    text = db.Column(db.String(500), nullable=False)
    link = db.Column(db.String(500), nullable=True)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


def add_notification(email, text, link=None):
    try:
        db.session.add(Notification(email=email, text=text, link=link))
        db.session.commit()
    except Exception:
        db.session.rollback()

def save_profile_picture(uploaded, owner_email=None,old_filename=None):
    folder = os.path.join(current_app.root_path, "static", "profile_pics")
    os.makedirs(folder, exist_ok=True)

    if owner_email:
        prefix_src = owner_email
    elif getattr(current_user, "is_authenticated", False):
        prefix_src = current_user.email
    else:
        prefix_src = "user"

    prefix = secure_filename(prefix_src.split("@")[0])
    filename = f"{prefix}_{secure_filename(uploaded.filename)}"
    path = os.path.join(folder, filename)

    if old_filename and old_filename != "default_image.png":
        old_path = os.path.join(folder, old_filename)
        if os.path.exists(old_path):
            try:
                os.remove(old_path)
            except PermissionError:
                tmp = old_path + ".old"
                try:
                    os.replace(old_path, tmp)
                    os.remove(tmp)
                except Exception:
                    pass
    try:
        uploaded.stream.seek(0)
    except Exception:
        pass

    uploaded.save(path)
    return filename

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


# Register page
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
        picture_file = "default_image.png"
        if "picture" in request.files and request.files["picture"].filename:
            picture_file = save_profile_picture(request.files["picture"], email)

        # Create user
        new_user = User(
            email=email,
            name=name,
            gender=gender,
            sport_level=sport_level,
            security_question=security_question,
            security_answer=security_answer,
            password=hashed_password,
            role="user",  # default role
            image_file=picture_file,
        )

        try:
            db.session.add(new_user)
            db.session.commit()

            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))  # direct to login page

        except IntegrityError:
            db.session.rollback()
            flash("Email already exists. Please log in.", "warning")
            return redirect(url_for("login"))

    return render_template("register.html", question=question)


# Login page
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
            flash("Incorrect password. Please try again.")
            return redirect(url_for("login"))

        if user.is_suspended:
            flash("Your account has been suspended. Contact admin for support.", "danger")
            return redirect(url_for("login"))

        # Login successful
        login_user(user)

        if user.role == 'admin':
            session['as_admin'] = True
        else:
            session['as_admin'] = False


        flash(f"Welcome back, {user.name}!")

        # Redirect based on role
        if user.role == "user":
            return redirect(url_for("posts"))   
        else:
            return redirect(url_for("admin_dashboard"))           

    return render_template("login.html")


@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        step = request.form.get("current")

        # Step 1: Enter email
        if step == "email":
            email = request.form.get("email", "").strip().lower()
            user = User.query.filter_by(email=email).first()

            if not user:
                flash("Email not found.", "warning")
                return render_template("login.html", open_reset_modal=True, question=question)

            security_question = question.get(
                user.security_question.strip().lower(),
                "Security question not found"
            )

            return render_template(
                "login.html",
                open_reset_modal=True,
                email=email,
                security_question=security_question,
                question=question
            )

        # Step 2: Submit answer & new password
        elif step == "reset":
            email = request.form.get("email", "").strip().lower()
            answer = request.form.get("security_answer", "").strip().lower()
            new_password = request.form.get("new_password", "")

            user = User.query.filter_by(email=email).first()
            if not user:
                flash("Email not found.", "warning")
                return render_template("login.html", open_reset_modal=True, question=question)

            if user.security_answer.lower() == answer:
                user.password = generate_password_hash(new_password, method="pbkdf2:sha256")
                db.session.commit()
                add_notification(user.email, "Your password was reset successfully.")
                flash("Password updated successfully!")
                return redirect(url_for("login"))
            else:
                flash("Security answer incorrect.", "danger")
                return render_template(
                    "login.html",
                    open_reset_modal=True,
                    email=email,
                    security_question=question.get(
                        user.security_question.strip().lower(),
                        "Security question not found"
                    ),
                    question=question
                )

    # Default: show reset modal
    return render_template("login.html", open_reset_modal=True, question=question)


@app.route("/index")
@login_required
def posts():
    # Default: show only non-hidden posts
    posts = Posts.query.filter_by(is_hidden=False).order_by(Posts.date_posted.desc()).all()

    for post in posts:
        if post.date_posted:
            if post.date_posted.tzinfo is None:
                utc_time = pytz.utc.localize(post.date_posted)
            else:
                utc_time = post.date_posted
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
    # Join User so we can filter by user name too
    query = Posts.query.join(User).filter(Posts.is_hidden == False)

    # Filter by sport if provided
    if sport:
        searched = True
        query = query.filter(
            or_(
                func.lower(Posts.title).like(f"%{sport}%"),
                func.lower(Posts.content).like(f"%{sport}%"),
                func.lower(Posts.location).like(f"%{sport}%"),
                func.lower(User.name).like(f"%{sport}%")   # ✅ works because Posts has FK -> User
            )
        )

    # Filter by date if provided
    if dateinpost:
        searched = True
        try:
            date_obj = datetime.strptime(dateinpost, "%Y-%m-%d").date()
            query = query.filter(Posts.event_date == date_obj)
        except ValueError:
            flash("Invalid date format. Please use YYYY-MM-DD.", "warning")

    # Execute query
    results = query.order_by(Posts.date_posted.desc()).all()

    # Convert posted date to Malaysia timezone
    for post in results: 
        if post.date_posted:
            if post.date_posted.tzinfo is None:
                utc_time = pytz.utc.localize(post.date_posted)
            else:
                utc_time = post.date_posted
            post.local_date_posted_value = utc_time.astimezone(MALAYSIA_TZ)
        else:
            post.local_date_posted_value = None

    # Detect if admin is logged in (for template use)
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

    # Force reload of locations for this form instance (add safe defaults for testing)
    form.location.choices = load_locations()
    if not form.location.choices or form.location.choices == [("none", "--Please select a location--")]:
        form.location.choices = []  # fallback choices
    
    if form.validate_on_submit():
        # Handle image upload
        image_file = form.image.data
        filename = None
        start_time = form.start_time.data
        end_time = form.end_time.data

        if start_time and end_time and end_time <= start_time:
            flash("End time must be after start time.", "danger")
            return render_template("create.html", form=form, current_date=date.today().isoformat())
        
        if image_file:
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(image_path)

        try:
            new_post = Posts(
                title=form.title.data,
                image_filename=filename,
                content=form.content.data,
                location=form.location.data,
                event_date=form.event_date.data,
                start_time=form.start_time.data,
                end_time=form.end_time.data,
                participants=form.participants.data,
                email=current_user.email if current_user.is_authenticated else session.get("admin_email"),
            )
            
            db.session.add(new_post)
            db.session.commit()
            flash("Post created successfully!", "success")
            return redirect(url_for("posts"))
        except Exception as e:
            print("Error creating post:", e)
            flash(f"Error creating post: {e}", "danger")

    return render_template("create.html", form=form, current_date=date.today().isoformat())


# Edit post
@app.route("/edit/<int:post_id>", methods=["GET", "POST"])
def edit_post(post_id):
    post = Posts.query.get_or_404(post_id)

    # Permission check
    if current_user.is_authenticated:
        is_owner = (post.email == current_user.email)
    elif session.get("admin_email"):
        is_owner = True  # admins can edit any post
    else:
        is_owner = False

    if not is_owner:
        flash("You are not authorized to edit this post.", "danger")
        return redirect(url_for("posts"))

    form = ActivityForm(obj=post)

    # Reload location choices
    form.location.choices = load_locations()
    if not form.location.choices or form.location.choices == [("none", "--Please select a location--")]:
        form.location.choices = [("Gym", "Gym"), ("Pool", "Pool")]

    if form.validate_on_submit():
        start_time = form.start_time.data
        end_time = form.end_time.data

        # Validate time logic
        if start_time and end_time and end_time <= start_time:
            form.end_time.errors.append("End time must be after start time.")
            return render_template("edit_post.html", form=form, post=post, current_date=date.today().isoformat())

        # Update post fields
        post.title = form.title.data
        post.content = form.content.data
        post.location = form.location.data
        post.event_date = form.event_date.data
        post.start_time = start_time
        post.end_time = end_time
        post.participants = form.participants.data

        # Handle new image upload
        if form.image.data:
            if post.image_filename:
                old_path = os.path.join(current_app.root_path, "static/uploads", post.image_filename)
                if os.path.exists(old_path):
                    os.remove(old_path)
            file = form.image.data
            filename = secure_filename(file.filename)
            file.save(os.path.join(current_app.root_path, "static/uploads", filename))
            post.image_filename = filename

        db.session.commit()
        flash("Post updated successfully!", "success")
        return redirect(url_for("post_detail", post_id=post.post_id))

    # Pre-fill form fields on GET
    if request.method == "GET":
        form.title.data = post.title
        form.content.data = post.content
        form.location.data = post.location
        form.event_date.data = post.event_date
        form.start_time.data = post.start_time
        form.end_time.data = post.end_time
        form.participants.data = post.participants

    return render_template("edit_post.html", form=form, post=post, current_date=date.today().isoformat())



# Delete post
@app.route("/delete/<int:post_id>", methods=["POST"])
def delete(post_id):
    if not current_user.is_authenticated and not session.get("admin_email"):
        flash("You must log in first.")
        return redirect(url_for("login"))

    post = Posts.query.get_or_404(post_id)

    # Permission check (user OR admin)
    if current_user.is_authenticated:
        is_author = (post.email == current_user.email)
    elif session.get("admin_email"):
        is_author = True  #  admins can delete any post
    else:
        is_author = False

    if not is_author:
        flash("You don't have permission to delete this post.", "danger")
        return redirect(url_for("posts"))

    # Delete image file if exists
    if post.image_filename:
        img_path = os.path.join(current_app.root_path, "static/uploads", post.image_filename)
        if os.path.exists(img_path):
            os.remove(img_path)

    db.session.delete(post)
    db.session.commit()
    flash("Post deleted successfully!", "danger")

    # If admin came from reports dashboard, send them back there
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

    # reporter can be either user.email or admin_email
    reporter_email = current_user.email if current_user.is_authenticated else session.get("admin_email")

    # Prevent duplicate reports by same reporter
    existing_report = Reports.query.filter_by(post_id=post_id, reporter_email=reporter_email).first()
    if existing_report:
        flash("You already reported this post.", "warning")
        return redirect(url_for("post_detail", post_id=post_id))

    # Create and commit the report
    new_report = Reports(post_id=post_id, reporter_email=reporter_email)
    db.session.add(new_report)
    db.session.commit()

    # Count total reports from Reports table and hide post if threshold reached
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

    # Force readonly for admins on first visit, while preserving origin flags
    if session.get("admin_email") and readonly is None:
        args = request.args.to_dict(flat=True)  # copy all current args
        args["readonly"] = 1                   # enforce readonly
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

    owner_email = post.email  # ✅ correct owner field

    # If current user is the owner → show conversations
    if current_user.is_authenticated and current_user.email.lower() == owner_email.lower():
        partners = (
            db.session.query(ChatMessage.sender_email)
            .filter_by(post_id=post.post_id)
            .distinct()
        )
        for (email,) in partners:
            if email.lower() != owner_email.lower():
                user = User.query.get(email)
                owner_conversations.append(
                    {"email": email, "name": user.name if user else email}
                )

    return render_template(
        "post_detail.html",
        post=post,
        join_activities=join_activities,
        owner_conversations=owner_conversations,
        readonly=readonly,
        from_reports=from_reports,
        from_dashboard=from_dashboard,
    )


def conversation_key(a_email: str, b_email: str) -> str:
    """Generate a stable key for two users’ conversation."""
    return "|".join(sorted([a_email.lower(), b_email.lower()]))


@app.route("/chat/<int:post_id>/<partner_email>")
@login_required
def chat_with_user(post_id, partner_email):
    post = Posts.query.get_or_404(post_id)
    owner_email = post.email.lower()
    current_email = current_user.email.lower()

    partner_email = partner_email.lower()

    # Prevent outsiders from chatting → only owner or partner allowed
    if current_email != owner_email and partner_email != owner_email:
        return redirect(url_for("chat_with_user", post_id=post_id, partner_email=owner_email))

    conv = conversation_key(current_email, partner_email)
    room = f"post-{post_id}-{conv}"

    messages = (
        ChatMessage.query.filter_by(post_id=post_id, conversation=conv)
        .order_by(asc(ChatMessage.created_at))
        .all()
    )

    for msg in messages:
        if msg.created_at:
            msg.local_time = pytz.utc.localize(msg.created_at).astimezone(MALAYSIA_TZ).strftime("%H:%M")
        else:
            msg.local_time = ""

    partner_user = User.query.get(partner_email)
    partner_name = partner_user.name if partner_user else partner_email
    partner_img = url_for("static", filename=f"profile_pics/{partner_user.image_file or 'default_image.png'}") if partner_user else url_for("static", filename="profile_pics/default.png")

    if current_email == owner_email:
        header_name = partner_name
    else:
        header_name = post.user.name  # ✅ uses Posts.user relationship

    return render_template("chat.html",post=post, room=room, username=current_user.name,header_name=header_name, 
                           messages=messages, post_id=post_id, partner_email=partner_email,partner_img=partner_img)

@socketio.on("join")
def on_join(data):
    room = data.get("room")

    # Identify sender
    if current_user.is_authenticated:
        name = current_user.name
        email = current_user.email
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

    # Support both users and admins as senders
    if current_user.is_authenticated:
        current_email = current_user.email.lower()
        sender_email = current_user.email
        sender_name = current_user.name
    elif session.get("admin_email"):
        sender_email = session.get("admin_email").lower()
        current_email = sender_email
        admin_obj = Admin.query.get(sender_email)
        sender_name = admin_obj.admin_name if admin_obj else "Admin"
    else:
        return  # nobody logged in, ignore

    conv = conversation_key(current_email, partner)

    msg = ChatMessage(
        post_id=int(post_id),
        conversation=conv,
        sender_email=sender_email,
        sender_name=sender_name,
        text=text,
    )
    db.session.add(msg)
    db.session.commit()

    if msg.created_at:
        utc_time = pytz.utc.localize(msg.created_at)
        local_time = utc_time.astimezone(MALAYSIA_TZ)
    else:
        local_time = None

    ts = local_time.strftime("%H:%M") if local_time else ""

    try:
        # ✅ Notify partner if it’s not the same as sender
        if partner != current_email:
            chat_url = url_for("chat_with_user", post_id=post_id, partner_email=sender_email)
            add_notification(partner, f"{sender_name} sent you a message", link=chat_url)
    except Exception:
        db.session.rollback()

    send({"user": msg.sender_name,"email": msg.sender_email ,"text": msg.text, "time": ts}, to=room)


# Notifications page
@app.route("/notifications")
@login_required
def notifications():
    rows = (
        Notification.query.filter_by(email=current_user.email)
        .order_by(Notification.created_at.desc())
        .all()
    )

    for notif in rows:
        if notif.created_at:
            if notif.created_at.tzinfo is None:
                notif.local_time = pytz.utc.localize(notif.created_at).astimezone(MALAYSIA_TZ)
            else:
                notif.local_time = notif.created_at.astimezone(MALAYSIA_TZ)
        else:
            notif.local_time = None

    return render_template("notifications.html", rows=rows)

@app.route("/notifications/read_all", methods=["POST"])
@login_required
def notifications_read_all():
    Notification.query.filter_by(email=current_user.email, is_read=False).update({"is_read": True})
    db.session.commit()
    return redirect(url_for("notifications"))


@app.route("/notif/<int:notif_id>")
@login_required
def open_notif(notif_id):
    notif = Notification.query.get_or_404(notif_id)

    if notif.email.lower() == current_user.email.lower():
        notif.is_read = True
        db.session.commit()

    return redirect(notif.link or url_for("notifications"))

#Delete notification
@app.route("/notifications/delete/<int:notif_id>", methods=["POST"])
@login_required
def notifications_delete(notif_id):
    notif = Notification.query.get_or_404(notif_id)
    if notif.email == current_user.email:
        db.session.delete(notif)
        db.session.commit()
    return redirect(url_for("notifications"))

@app.route("/notifications/clear", methods=["POST"])
@login_required
def notifications_clear():
    Notification.query.filter_by(email=current_user.email).delete()
    db.session.commit()
    return redirect(url_for("notifications"))

#My profile
@app.route("/profile")
@login_required
def profile():
    return redirect(url_for("profile_page", email=current_user.email))


@app.route("/profile/<string:email>")
@login_required
def profile_page(email):
    # fetch the user being viewed by email
    user = User.query.filter_by(email=email).first_or_404()

    # fetch only this user's posts
    recent_posts = (
        Posts.query.filter_by(email=user.email)
        .order_by(Posts.date_posted.desc())
        .all()
    )

    # Convert posted date to Malaysia timezone
    for post in recent_posts:
        if post.date_posted:
            if post.date_posted.tzinfo is None:
                utc_time = pytz.utc.localize(post.date_posted)
                post.local_date_posted_value = utc_time.astimezone(MALAYSIA_TZ)
            else:
                post.local_date_posted_value = post.date_posted.astimezone(MALAYSIA_TZ)
        else:
            post.local_date_posted_value = None

    # correct image path (use their image, not always current_user)
    image_url = url_for(
        "static",
        filename=f"profile_pics/{user.image_file or 'default_image.png'}"
    )

    return render_template(
        "profile.html",
        user=user,
        image_url=image_url,
        recent_posts=recent_posts
    )



@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def profile_edit():
    form = UpdateProfileForm()

     # Set the choices dynamically
    form.security_question.choices = list(question.items())

    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.gender = form.gender.data
        current_user.sport_level = form.sport_level.data
        current_user.bio = form.bio.data or None
        current_user.security_question = form.security_question.data
        current_user.security_answer = (form.security_answer.data or "").strip().lower()

        uploaded = request.files.get("picture")
        if uploaded and uploaded.filename:
            current_user.image_file = save_profile_picture(uploaded, current_user.email, current_user.image_file)

        db.session.commit()
        flash("Profile updated.")
        return redirect(url_for("profile"))
    
    if request.method == "GET":
        form.name.data = current_user.name
        form.gender.data = current_user.gender
        form.bio.data = current_user.bio
        form.security_question.data = current_user.security_question
        form.security_answer.data = current_user.security_answer

    image_url = url_for("static", filename=f"profile_pics/{current_user.image_file or 'default_image.png'}")

    return render_template("edit_profile.html", form=form, image_url=image_url, question=question)



def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext.lower()
    picture_path = os.path.join(app.root_path, "static/profile_pics", picture_fn)

    try:
        img = Image.open(form_picture)
        img.thumbnail((256, 256))
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
        flash("You already requested this activity.")
    else:
        join_act = JoinActivity(email=current_user.email, post_id=post.post_id)
        db.session.add(join_act)
        db.session.commit()
        flash("Your request has been sent to the post owner.")

        add_notification(
            post.email,
            f"{current_user.name} requested to join '{post.title}'",
            link=url_for("post_detail", post_id=post.post_id)
        )

    return redirect(url_for("post_detail", post_id=post.post_id))


# Handle Join Activity requests
@app.route("/handleactivity/<int:request_id>/<string:decision>", methods=["POST"])
@login_required
def handle_request(request_id, decision):
    join_activity = JoinActivity.query.get_or_404(request_id)
    post = join_activity.post

    # Only the post owner can handle requests
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
            flash(f"{join_activity.user.name if join_activity.user else join_activity.email} has been accepted!")

            add_notification(
                join_activity.email,
                f"Your request for '{post.title}' was accepted",
                link=url_for("post_detail", post_id=post.post_id)
            )

            accepted_count += 1
            if accepted_count >= post.participants:
                post.post_status = "closed"
                flash("The activity is now full and closed.")
        else:
            flash("This activity already has enough participants.")

    elif decision == "reject":
        join_activity.status = "rejected"
        flash(f"{join_activity.user.name if join_activity.user else join_activity.email} has been rejected.")

        add_notification(join_activity.email, f"Your request for '{post.title}' was rejected",link=url_for("post_detail", post_id=post.post_id))

    db.session.commit()
    return redirect(url_for("post_detail", post_id=post.post_id))



#admin interface
# Create default first admin
def create_first_admin():
    existing_admin = User.query.filter(User.role.in_(["admin"])).first()
    
    if not existing_admin:
        admin_user = User(
            email="eewen@gmail.com",
            name="Lee Ee Wen",
            password=generate_password_hash("aaaa", method="pbkdf2:sha256"),
            gender="Female",
            sport_level="Advanced",
            security_question="book",  #  key from the question dict
            security_answer="Cinderella",
            role="admin"
        )
        db.session.add(admin_user)
        db.session.commit()



# REQUEST ADMIN ACCESS
@app.route("/request_admin", methods=["GET", "POST"])
def request_admin():
    email = request.form.get("email", "").strip().lower()

    # Prevent existing admins from submitting requests
    existing_user = User.query.filter_by(email=email).first()
    if existing_user and existing_user.role in ["admin"]:
        flash("You are already an admin. Please log in.")
        return redirect(url_for("login"))

    step = request.form.get("step", "email")

    if step == "email" and request.method == "POST":
        return render_template("request_admin.html", email=email, existing_user=existing_user,question=question)

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
            sec_question = existing_user.security_question #pass as hidden input as existing user alr key in whe register
            sec_answer = existing_user.security_answer #hidden input
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

    return render_template("request_admin.html",question=question)

        
# HANDLE REQUEST (any logged-in admin can approve/reject)
@app.route("/handle-request/<int:approval_id>", methods=["GET", "POST"])
@login_required
def handle_request_admin(approval_id):
    if current_user.role not in ["admin"]:
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
    if current_user.role not in ["admin"]:
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
            if user and user.role in ["admin"]:
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
        admin=current_user,
        users=users,
        posts=posts,
        is_admin=True
    )


# Admin delete user
@app.route("/admin/delete_user/<string:email>", methods=["POST"])
@login_required
def delete_user(email):
    if current_user.role != "admin":
        abort(403)

    # Prevent admin from deleting their own account
    if current_user.email.lower() == email.lower():
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("admin_dashboard"))

    user = User.query.filter_by(email=email.lower()).first_or_404()
    db.session.delete(user)
    db.session.commit()

    flash("User deleted successfully.", "success")
    return redirect(url_for("admin_dashboard"))


# Admin reports
@app.route("/admin/reports")
@login_required
def admin_reports():
    if current_user.role != "admin":
        abort(403)

    flagged_posts = (
        db.session.query(Posts, db.func.count(Reports.id).label("report_count"))
        .join(Reports, Reports.post_id == Posts.post_id)
        .group_by(Posts.post_id)
        .having(db.func.count(Reports.id) >= 3)  # threshold
        .all()
    )

    suspended_users = User.query.filter_by(is_suspended=True).all()

    return render_template(
        "admin_reports.html",
        flagged_posts=flagged_posts,
        suspended_users=suspended_users
    )

# Suspend user
@app.route("/suspend/<string:email>", methods=["POST"])
@login_required
def suspend_user(email):
    if current_user.role != "admin":
        abort(403)

    user = User.query.filter_by(email=email.lower()).first_or_404()
    user.is_suspended = True
    db.session.commit()

    flash(f"User {user.email} has been suspended.", "warning")
    return redirect(url_for("admin_reports"))


# Unsuspend user
@app.route("/unsuspend/<string:email>", methods=["POST"])
@login_required
def unsuspend_user(email):
    if current_user.role != "admin":
        abort(403)

    user = User.query.filter_by(email=email.lower()).first_or_404()
    user.is_suspended = False
    db.session.commit()

    flash(f"User {user.email} has been unsuspended.", "success")
    return redirect(url_for("admin_dashboard"))



# Reactivate hidden post
@app.route("/reactivate/<int:post_id>", methods=["POST"])
@login_required
def reactivate_post(post_id):
    if current_user.role != "admin":
        abort(403)

    post = Posts.query.get_or_404(post_id)
    post.is_hidden = False

    # Remove all reports tied to this post
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


# Upload location list
import io

@app.route("/admin/updatelocation", methods=["GET", "POST"])
@login_required
def upload_location_csv():
    if current_user.role not in ["admin"]:
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

@app.route("/user/<string:email>")
@login_required
def view_user_profile(email):
    user = User.query.get_or_404(email)
    return render_template("profile.html", user=user)

# Switch to admin view
@app.route("/switch_to_admin")
def switch_to_admin():
    if not current_user.is_authenticated or current_user.role != 'admin':
        flash("You cannot switch to admin view.", "danger")
        return redirect(url_for('posts'))

    session['as_admin'] = True
    flash("Switched to Admin view.", "success")
    return redirect(url_for('admin_dashboard'))


# Switch to user view
@app.route("/switch_to_user")
def switch_to_user():
    if not current_user.is_authenticated:
        flash("You need to login first!", "danger")
        return redirect(url_for('login'))

    session['as_admin'] = False
    flash("Switched to User view.", "success")
    return redirect(url_for('posts'))



# Run app
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        create_first_admin()
    app.run(debug=True)