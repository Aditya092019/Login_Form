import os
import pathlib
from flask import Flask, abort, redirect, render_template, request, session, url_for, flash, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, ValidationError
import bcrypt
from flask_mysqldb import MySQL
import mysql.connector
from mysql.connector import errorcode
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests
import requests
from pip._vendor import cachecontrol


app = Flask(__name__)

# MySQL Configuration
app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = "7486"
app.config["MYSQL_DB"] = "db"
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY']= SECRET_KEY

mysql = MySQL(app)



# # Google OAuth setup
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "86621445224-19r9bg9o6ud14qr0kon5qrpgnodt8mak.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

# app1 = Flask("Google Login App")    
app.secret_key = "CodeSpecialist.com"


class RegisterForm(FlaskForm):
    name = StringField("Name",validators=[DataRequired()])
    email = StringField("Email",validators=[DataRequired(), Email()])
    password = PasswordField("Password",validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self,field):
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users where email=%s",(field.data,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            raise ValidationError('Email Already Taken')

class LoginForm(FlaskForm):
    email = StringField("Email",validators=[DataRequired(), Email()])
    password = PasswordField("Password",validators=[DataRequired()])
    submit = SubmitField("Login")




def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)
        else:
            return function()
    return wrapper    


@ app.route("/")
def index():
    return render_template("index.html")


@app.route('/register',methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data

        hashed_password = bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt(12))

        # store data into database 
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users (name,email,password) VALUES (%s,%s,%s)",(name,email,hashed_password))
        mysql.connection.commit()
        cursor.close()

        return redirect(url_for('login'))

    return render_template('register.html',form=form)



@ app.route("/login1", methods = ["GET","POST"])
def login1():    
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)
    

@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        print("........fghjhfdgtghh........")
        print("---------------------",mysql)
        email = form.email.data
        password = form.password.data

        print("......... Email.........",email,password)
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=(%s)",(email,))
        user = cursor.fetchone()
        print(user)
        cursor.close()
        print(user[3])
        print(user[3].encode('utf-8'))
        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            session['user_id'] = user[0]
            return redirect(url_for('dashboard'))
        else:
            flash("Login failed. Please check your email and password")
            return redirect(url_for('login'))

    return render_template('login.html',form=form)




@app.route("/callback")
def callback():
    
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)          
    
    credentials = flow.credentials
    request_session = requests.Session()
    cached_session = cachecontrol.CacheControl(request_session) 
    token_request = google.auth.transport.requests.Request(session=cached_session) 

    id_info = id_token.verify_oauth2_token( 
        id_token = credentials._id_token,
        request = token_request,
        audience = GOOGLE_CLIENT_ID
    )
    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")  
    session["email"] = id_info.get("email") 


    cursor = mysql.connection.cursor()
    ram = id_info.get("email")
    found = cursor.execute("SELECT * FROM users WHERE email=(%s)",(id_info.get("email"),))
    bool = False
    try:
        if found == 0:
            cursor.execute("INSERT INTO users (name,email,password) VALUES (%s,%s,%s)",(id_info.get("name"),id_info.get("email"),id_info.get("sub")))
    except Exception as e:
      print(e)
    mysql.connection.commit()
    cursor.execute("SELECT * FROM users WHERE email=(%s)",(id_info.get("email"),))
    user = cursor.fetchone()
    cursor.close()

    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'google_id' in session:
        return render_template('dashboard.html',user={"name":session["name"],"email":session["email"]})
        
    if 'user_id' in session:
        user_id = session['user_id']
    

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users where id=%s",(user_id,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            return render_template('dashboard.html',user={"name":user[1],"email":user[2]})
            
    return redirect(url_for('login'))



@ app.route("/logout")
def logout():
    if 'user_id' in session:
        session.pop('user_id', None)
    if 'google_id' in session:
         session.pop('name', None)
         session.pop('email', None)
         session.pop('google_id', None)    
    flash("You have been logged out successfully.")
    return redirect(url_for('login'))

 

@app.route('/api/allusers', methods=['GET'])
def get_table_data():
    cursor =  mysql.connection.cursor()
    
    cursor.execute(f"SELECT * FROM users")
    
    rows = cursor.fetchall()
    cursor.close()
    return jsonify(rows)



if __name__ == "__main__":
    app.run(debug=True)
