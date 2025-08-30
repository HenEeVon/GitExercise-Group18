from flask import Flask, request, redirect, url_for, render_template

app = Flask(__name__)

activity_posts = []
next_id = 0

@app.route("/")
def home():
    return render_template("index.html", posts=activity_posts)

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

@app.route("/delete/<int:post_id>", methods=["POST"])
def delete(post_id):
    global activity_posts
    activity_posts = [post for post in activity_posts if post["id"] != post_id]
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)