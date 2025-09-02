from flask import Flask, render_template, url_for, request, redirect
import sqlite3
import os

app = Flask(__name__)

# finding database path which store data in the root folder of projects
DB_path = os.path.join(os.path.dirname(__file__), "user.db")

#Database setup
def init_db():
    with sqlite3.connect(DB_path) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users(
                user_email TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                gender NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()

def get_users():
    with sqlite3.connect(DB_path) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users')
        return cursor.fetchall()

def add_user(user_email, name, gender, password):
    with sqlite3.connect(DB_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO users (user_email, name, gender, password) VALUES (?, ?, ?, ?)',
            (user_email, name, gender, password)
        )
        conn.commit()

@app.route("/")
def home():
    return render_template('home.html')

@app.route("/register", methods=['POST','GET'])
def register():
    if request.method =='POST':
        user_email = request.form['user_email'].strip().lower() 
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
        email = request.form['user_email'].strip().lower() 
        password = request.form['password']
        users = get_users()
        for user in users:
            if user[0] == email and user[3] == password:  #user[0]is index of email
                return f"Login successful! Welcome {user[1]}"
            
            message = "User not Found. Invalid email or password !!!" #loop finishes without returning

    return render_template('login.html', message=message)

@app.route("/resetpass", methods=['GET','POST'])
def resetpass():
    if request.method == 'POST':
        user_email = request.form.get('email')       # match the input name in HTML
        new_password = request.form.get('new_password')

        if not user_email or not new_password:
            return 'Email and new password are required!', 400 # 400 for bad request,missing or invalid input

        with sqlite3.connect(DB_path) as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE user_email = ?', (user_email,))
            user = c.fetchone()
            if user:
                # Update password
                c.execute('UPDATE users SET password = ? WHERE user_email = ?', (new_password, user_email))
                conn.commit()
                return 'Password updated successfully!'
            else:
                return 'Email not found!'

    return render_template('resetpass.html')


if __name__ =='__main__':
    init_db()
    app.run(debug=True)