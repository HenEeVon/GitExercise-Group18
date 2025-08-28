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
    cursor.execute("DROP TABLE IF EXISTS users")
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users(
            user_email TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            gender NOT NULL,
            password TEXT NOT NULL
            
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
def add_user(user_email,name,gender,password):
    conn = sqlite3.connect(DB_path)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (user_email,name,gender,password) VALUES (?,?,?,?)',(user_email, name,gender,password))
    conn.commit()
    conn.close()

@app.route("/")
def home():
    return render_template('home.html')

@app.route("/register", methods=['POST','GET'])
def register():
    if request.method =='POST':
        user_email = request.form['user_email']
        name = request.form['name']
        gender = request.form['gender']
        password = request.form['password']
        add_user(user_email,name,gender,password)
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    message = ''
    if request.method == 'POST':
        email = request.form['user_email']
        password = request.form['password']
        users = get_users()
        for user in users:
            if user[0] == email and user[2] == password: 
                return f"Login successful! Welcome {user[1]}"
        message = "Invalid email or password"

    return render_template('login.html', message=message)

if __name__ =='__main__':
    init_db()
    app.run(debug=True)