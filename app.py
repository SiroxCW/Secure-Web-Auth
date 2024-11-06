
from flask import Flask, request, redirect, url_for, render_template
import requests
import jwt
import datetime
from src import user
from json import load

with open("config.json") as file:
    config = load(file)


app = Flask(__name__)
app.config['SECRET_KEY'] = config['auth']['secret']

def create_token():
    expiration = datetime.datetime.utcnow() + datetime.timedelta(seconds=config['auth']['expires'])
    token = jwt.encode({'exp': expiration}, app.config['SECRET_KEY'], algorithm='HS256')
    return token

def verify_token(token):
    try:
        jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return True
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidTokenError:
        return False

@app.route("/")
def home():
    token = request.cookies.get('token')
    logged_in = token and verify_token(token)
    return render_template("index.html", logged_in=logged_in)

@app.route("/info")
def info():
    return render_template("info.html")

@app.route("/verify", methods=['GET'])
def verify():
    emailToken = request.args.get('token')
    if user.email_check_token(emailToken, config):
        return "Yasss"
    return "Nooo"

@app.route("/register", methods=['GET', 'POST'])
def register():
    error = ""
    if request.method == 'POST':
        turnstile_response = request.form.get('cf-turnstile-response')
        if not turnstile_response or not verify_turnstile(turnstile_response):
            error = "Turnstile verification failed."
            return render_template("register.html", error=error)

        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if user.register(username, email, password, config):
            user.email_send_verification(username, config, email)
            response = redirect(url_for('info'))
            return response
        else:
            error = "Username or Email already used."
    return render_template("register.html", error=error)

@app.route("/login", methods=['GET', 'POST'])
def login():
    error = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        success, error = user.login(username, password, config)
        if success:
            token = create_token()
            response = redirect(url_for('home'))
            response.set_cookie('token', token)
            return response
    return render_template("login.html", error=error)

def verify_turnstile(response):
    secret_key = config['auth']['cloudflare_secret']
    payload = {
        'secret': secret_key,
        'response': response
    }
    verify_url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    result = requests.post(verify_url, data=payload)
    return result.json().get('success', False)

if __name__ == '__main__':
    app.run(port=4321, host='0.0.0.0')
