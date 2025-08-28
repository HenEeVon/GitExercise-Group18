from flask import Flask, render_template, url_for, request, redirect
import sqlite3
import os

app = Flask(__name__)

# finding database path which store data in the root folder of projects
DB_path = os.path.join(os.path.dirname(__file__), "user.db")

#Database setup
def init_db():
    conn=sqlite3.connect(DB_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users(
            user_email TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            gender TEXT NOT NULL
                   )
                   
                   ''')
    conn.commit()
    conn.close()

# Get all users from the database
def get_users():
    conn=sqlite3.connect(DB_path)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    conn.close()
    return users

# Add new user to database
def add_user(user_email,name,gender):
    conn = sqlite3.connect(DB_path)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (user_email,name,gender) VALUES (?,?,?)',(user_email, name,gender))
    conn.commit()
    conn.close()

@app.route("/")
def home():
    return render_template('home.html')

@app.route("/register", methods=['POST'])
def register():
    user_email = request.form['user_email']
    name = request.form['name']
    gender = request.form['gender']
    add_user(user_email,name,gender)
    return redirect(url_for('login'))

@app.route("/login")
def login():
    users = get_users()
    return render_template('login.html', users=users)

if __name__ =='__main__':
    init_db()
    app.run(debug=True)