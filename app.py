from flask import Flask, request, redirect, url_for, render_template, flash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import pytz

MALAYSIA_TZ = pytz.timezone("Asia/Kuala_Lumpur")

app = Flask(__name__)
# add database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///posts.db"
# secret key
app.config['SECRET_KEY'] = "060226*"
# initialize the database
db = SQLAlchemy(app)

# posts database model
class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    content = db.Column(db.Text)
    author = db.Column(db.String(255))
    location = db.Column(db.String(255))
    event_date = db.Column(db.DateTime)
    date_posted = db.Column(db.DateTime, default=lambda: datetime.utcnow().replace(tzinfo=pytz.utc))

    def local_event_date(self):
        if self.event_date is None:
            return None
        return utc_dt.astimezone(MALAYSIA_TZ)

    def local_date_posted(self):
        if self.date_posted is None:
            return None
        return self.date_posted.replace(tzinfo=pytz.utc).astimezone(MALAYSIA_TZ)

# Flask-WTF form
class ActivityForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    content = StringField("Content", validators=[DataRequired()])
    location = StringField("Location", validators=[DataRequired()])
    submit = SubmitField("Post")

@app.route("/")
def home():
    posts = Posts.query.order_by(Posts.date_posted.desc()).all()
    posts = Posts.query.order_by(Posts.date_posted.desc()).all()
    for post in posts:
        # event_date handling
        if post.event_date:
            post.local_event_date = post.event_date.replace(tzinfo=pytz.utc).astimezone(MALAYSIA_TZ)
        else:
            post.local_event_date = None

        # posted date handling
        if post.date_posted:
            post.local_date_posted = post.date_posted.replace(tzinfo=pytz.utc).astimezone(MALAYSIA_TZ)
        else:
            post.local_date_posted = None
    return render_template("index.html", posts=posts)

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
            event_date=datetime.utcnow().replace(tzinfo=pytz.utc)
        )
        db.session.add(new_post)
        db.session.commit()
        flash("Activity post created successfully!")
        return redirect(url_for("home"))
    return render_template("create.html", form=form)

# delete post
@app.route("/delete/<int:post_id>", methods=["POST"])
def delete(post_id):
    post = Posts.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    flash("Post deleted successfully!")
    return redirect(url_for("home"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
