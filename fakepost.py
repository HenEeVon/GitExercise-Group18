from app import app, db, Activity
from datetime import date

with app.app_context():
    db.drop_all()
    db.create_all()

    fakepost = [
        Activity (title="Finding One Partner for Badminton", category="badminton", date = date(2025,9,6), location="Badminton court MMU", gender="Male"),
        Activity (title="Casual match Tennis", category="tennis", date = date(2025,9,16), location="tennis court MMU", gender="Female"),        
        Activity (title="Gym partner lifting", category="gym", date = date(2025,10,21), location="Gym room MMU", gender="Male"),
        Activity (title="Join Badminton with me", category="badminton", date = date(2025,10,10), location="Dewan MMU", gender="Female"),
        Activity (title="Swimming day yayy", category="swim", date = date(2025,9,9), location="Swimming Pool MMU", gender="Male")
    ]        
              

    db.session.add_all(fakepost)
    db.session.commit()
    print("fake activity posts")
