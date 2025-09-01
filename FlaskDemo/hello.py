from flask import Flask, render_template, request
from activitydb import db, Activity
from sqlalchemy import func
from datetime import datetime

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///FLASKDEMO.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)


@app.route("/", methods = ["GET"])
def home():
    sport = (request.args.get("sport") or "" ).strip().lower()
    dateinpost = request.args.get("date")
    results =[]
    searched = False

    if sport:
        searched =True
        results = Activity.query.filter(func.lower(Activity.category).like(f"%{sport}%")).all()
    elif dateinpost:
        searched = True
        datechosen = dateinpost.strptime(dateinpost, "%Y-%m-%d").date()
        results = Activity.query.filter(Activity.date == datechosen).all()

    return render_template("search.html", results=results, searched = searched, sport=sport, date = dateinpost)

    
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)


