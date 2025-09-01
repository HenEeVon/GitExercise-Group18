from flask import Flask, render_template, request
from activitydb import db, Activity
from sqlalchemy import func

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///FLASKDEMO.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)


@app.route("/", methods = ["GET"])
def home():
    sport = (request.args.get("sport") or "" ).strip().lower()
    searched = bool(sport)

    results = []
    if searched:
        results = Activity.query.filter(func.lower(Activity.category).like(f"%{sport}%")).all()
    return render_template("search.html", results=results, searched = searched, sport=sport)
    
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)


