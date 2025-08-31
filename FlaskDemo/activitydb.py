from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()

class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String)
    category = db.Column(db.String)
    date = db.Column(db.Integer)
    location = db.Column(db.String)
    gender = db.Column(db.String)



    

