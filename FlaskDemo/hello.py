from flask import Flask, render_template, request
from activitydb import db, Activity
from sqlalchemy import func

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///FLASKDEMO.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)


@app.route("/")
def home():
    return render_template("search.html", results = [], searched = False, sport = None)


@app.route("/search/<sport>")
def search(sport):
    sport = sport.lower()
    results = (Activity.query.filter(func.lower(Activity.category).like(f"%{sport}%"))).all()
    return render_template("search.html", results=results, searched = True, sport=sport)
    

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)


