from flask import Flask, request, redirect, url_for, render_template, flash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime


app = Flask(__name__)
# add database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///posts.db"
# secret key
app.config['SECRET_KEY'] = "060226*"
# initialize the database
db = SQLAlchemy(app)

# create a activity post model
class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    content = db.Column(db.Text)
    author = db.Column(db.String(255))
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)


# create a form class
class NameForm(FlaskForm):
    name = StringField("What's your name",validators=[DataRequired()])
    submit = SubmitField("Submit")



activity_posts = []
next_id = 0

@app.route("/")
def home():
    return render_template("index.html", posts=activity_posts)

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"),404 

# create post form
@app.route("/create", methods=["GET", "POST"])
def create():
    global next_id
    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]
        date = request.form["date"]
        location = request.form["location"]

        # store activity post with unique ID
        activity_posts.append({
            "id": next_id,
            "title": title,
            "content": content,
            "date": date,
            "location": location
        })
        next_id += 1
        return redirect(url_for("home"))
    return render_template("create.html")

# delete post
@app.route("/delete/<int:post_id>", methods=["POST"])
def delete(post_id):
    global activity_posts
    activity_posts = [post for post in activity_posts if post["id"] != post_id]
    return redirect(url_for("home"))




if __name__ == "__main__":
    app.run(debug=True)