from flask import Flask, request, session, redirect, url_for, render_template
import os

app = Flask(__name__)

app.secret_key = "sup3r_s3cr3t_ctf_k3y_727"
users_db = {}

@app.before_request
def before_request():
    if "debug" in request.args:
        try:
            with open( __file__, 'r') as f:
                source_code = f.read()
            return f"<body style='background:#1e1e1e; color:#d4d4d4;'><pre>{source_code}</pre></body>"
        except Exception as e:
            print(f"Error reading file: {e}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            error = "Please provide both username and password."
        elif username == 'admin':
            error = "Error: Registration for the 'admin' account is prohibited."
        elif username in users_db:
            error = "Username already exists. Please choose another."
        else:
            users_db[username] = password
            return redirect(url_for('login'))

    return render_template('register.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == 'admin':
            error = "Error 403: Admin login via web interface is disabled."
        elif username in users_db and users_db[username] == password:
            session['username'] = username
            return redirect(url_for('flag'))
        else:
            error = "Invalid credentials or user does not exist."

    return render_template('login.html', error=error)

@app.route('/flag')
def flag():
    user = session.get('username')
    if user == 'admin':
        flag = os.environ.get('FLAG', "Something went wrong with the environment variable setup.")
        return render_template('flag.html', admin=True, flag=flag)
    elif user:
        return render_template('flag.html', admin=False, user=user)
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)