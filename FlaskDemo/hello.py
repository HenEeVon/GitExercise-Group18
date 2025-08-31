from flask import Flask, render_template, request
from activitydb import db, Activity

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///FLASKDEMO.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)


@app.route("/")
def home():
    return render_template("search.html", results = [])


@app.route("/search/<sport>")
def search(sport):
    sport = sport.lower()
    results = (Activity.query.filter(func.lower(Activity.category).like(f"%{sport}%"))).all()
    



@app.route("/user/<name>")
def user(name):
    return f"Hello {name}!"


if __name__ == "__main__":
    app.run(debug=True)


