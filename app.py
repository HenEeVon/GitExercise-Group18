from flask import Flask, request, redirect, url_for, render_template, flash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import pytz

MALAYSIA_TZ = pytz.timezone("Asia/Kuala_Lumpur")
UTC = pytz.utc

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
        flash("Post created successfully!")
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
        flash("Post Has Been Updated!")
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
    flash("Post deleted successfully!")
    return redirect(url_for("home"))


@app.route("/post/<int:post_id>")
def post_detail(post_id):
    post = Posts.query.get_or_404(post_id)
    post.local_date_posted_value = post.local_date_posted()
    return render_template("post_detail.html", post=post)



if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
