from flask import Flask, redirect, url_for, render_template

app = Flask(__name__)

"""
a = False
"""

activities = ["Archery","Badminton","Football","Rugby","Swimming"]

posts = [
    {"id": 1, "title": "Find a partner for Archery!!", "content": "If you r interested, pls contact me", "author": "Eevon" },
    {"id": 2, "title": "Please join me in Badminton!!", "content": "If you r free, pls contact me", "author": "Eevee" },
    {"id": 3, "title": "Yoo, u want to swim?", "content": "If you r professional, pls contact me", "author": "Eevery" }
    ]

@app.route("/")
def home():
    return render_template("home.html", act = activities, posts=posts)


app.route("/", methods=["GET","POST"])


@app.route("/search", methods=["POST"] )
def search():
    return "Search engine not yet done"



@app.route("/user/<name>")
def user(name):
    return f"Hello {name}!"

"""
@app.route("/admin")
def admin():
    if a:
        return "Hello, admin. What r u doin?"
    else:
        return redirect(url_for("home"))

"""

if __name__ == "__main__":
    app.run(debug=True)


