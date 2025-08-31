from hello import app, db, Activity

with app.app_context():
    db.drop_all()
    db.create_all()

    fakepost = [
        Activity (title="Finding One Partner for Badminton", category="badminton", date="31-8-2025", location="Badminton court MMU", gender="Male"),
        Activity (title="Casual match Tennis", category="tennis", date="10-9-2025", location="tennis court MMU", gender="Female"),        
        Activity (title="Gym partner lifting", category="gym", date="5-10-2025", location="Gym room MMU", gender="Male")
    ]        
              

    db.session.add_all(fakepost)
    db.session.commit()
    print("fake activity posts")
