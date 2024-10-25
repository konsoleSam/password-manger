#!Placeholder for linux shebang
import sys
import logging
import platform
import hashlib
import datetime
import secrets
import webview
import waitress
import socket
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask,render_template,flash,redirect,url_for,request,session#,Blueprint,send_file,send_from_directory,abort,make_response,jsonify# ,Markup
from flask_login import login_required,current_user,LoginManager,UserMixin,login_user,logout_user,AnonymousUserMixin#,fresh_login_required
from flask_sqlalchemy import SQLAlchemy
# from itsdangerous import URLSafeTimedSerializer
# from flask.sessions import SecureCookieSessionInterface
from markupsafe import Markup

app=Flask(__name__)

# check if app is compiled
FROZEN=getattr(sys, 'frozen', False)
if FROZEN:
    DIRECTORY=os.path.dirname(sys.executable)
else:
    DIRECTORY=os.path.dirname(__file__)

app.instance_path=os.path.join(DIRECTORY,"instance")
app.template_folder=os.path.join(DIRECTORY,"templates")
app.static_folder=os.path.join(DIRECTORY,"static")
if not os.path.exists(app.instance_path):
    os.mkdir(app.instance_path)

# Determine if the app is being run in debug mode
DEBUG=sys.gettrace()!=None

SERVER=False
DEVELOPMENT=False
logger=logging.getLogger(__name__)
if DEBUG:
    logging.basicConfig(filename=os.path.join(app.instance_path,'app_debug.log'), level=logging.INFO)
else:
    logging.basicConfig(filename=os.path.join(app.instance_path,'app.log'), level=logging.INFO)
node=platform.node()
logger.info(node)
logger.info("DEBUG "+str(DEBUG))

logger.info("DIRECTORY "+DIRECTORY)

# Generate the secret key
# os.urandom(32).hex()
# secrets.token_hex(32)
app.config["SECRET_KEY"]=secrets.token_hex(32)

# serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# For postgresql, example://scott:tiger@localhost/project
if DEBUG:
    app.config["SQLALCHEMY_DATABASE_URI"]="sqlite:///debug_database.sqlite"
else:
    app.config["SQLALCHEMY_DATABASE_URI"]="sqlite:///database.sqlite"

app.config["SQLALCHEMY_BINDS"]={}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]=False
app.config["REMEMBER_COOKIE_NAME"]="remember_token"
app.config["REMEMBER_COOKIE_DURATION"]=datetime.timedelta(days=365)
app.config["REMEMBER_COOKIE_DOMAIN"]=None
app.config["REMEMBER_COOKIE_PATH"]="/"
app.config["REMEMBER_COOKIE_SECURE"]=False
app.config["REMEMBER_COOKIE_HTTPONLY"]=True
app.config["REMEMBER_COOKIE_REFRESH_EACH_REQUEST"]=False
app.config["REMEMBER_COOKIE_SAMESITE"]=None

database=SQLAlchemy()
database.init_app(app)

# https://flask-login.readthedocs.io/en/latest/
class AnonymousUser(AnonymousUserMixin):
    def __init__(self):
        super().__init__()
        self.identity="guest"

# SQL Alchemy data types: https://docs.sqlalchemy.org/en/20/core/type_basics.html
# https://flask-sqlalchemy.palletsprojects.com/en/2.x/models/
class User(UserMixin, database.Model):
    __tablename__="user"
    id=database.Column(database.Integer,primary_key=True)
    identity=database.Column(database.String(32),unique=True)
    verifier=database.Column(database.String(64),nullable=False)
    salt=database.Column(database.String(32),nullable=True)
    created=database.Column(database.DateTime,default=lambda: datetime.datetime.now(tz=datetime.timezone.utc))
    last_updated=database.Column(database.DateTime,onupdate=lambda: datetime.datetime.now(tz=datetime.timezone.utc))
    active=database.Column(database.Boolean,default=True)
    files=database.relationship("UserFile",backref="user",lazy=True)

class UserFile(database.Model):
    __tablename__="user_file"
    id=database.Column(database.Integer, primary_key=True)
    created=database.Column(database.DateTime,default=lambda: datetime.datetime.now(tz=datetime.timezone.utc))
    last_updated=database.Column(database.DateTime,onupdate=lambda: datetime.datetime.now(tz=datetime.timezone.utc))
    data=database.Column(database.BLOB,default=None)
    name=database.Column(database.String(32))
    user_id=database.Column(database.Integer,database.ForeignKey('user.id'),nullable=False)

# Login manager
login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view="login"
# Login security strength
login_manager.session_protection="strong"
login_manager.anonymous_user=AnonymousUser

# Create variables for templates to use
@app.context_processor
def template_constants():
    return dict(VERSION="V10.25.24",
                DEBUG=DEBUG,
                SERVER=SERVER,
                DEVELOPMENT=DEVELOPMENT
                )
# Redirect errors through styled html page
@app.errorhandler(404)
def page_not_found(e):
    flash(e,"danger")
    return render_template("base.html")

@app.login_manager.unauthorized_handler
def unauthorized_handler():
    # if request.is_xhr:
    flash("You must be signed in!","danger")
    return redirect(url_for("sign_in"))

@login_manager.user_loader
def load_user(user_id):
    return database.session.get(User,user_id)

@app.route("/",methods=["GET","POST"])
def index():
    return render_template("index.html")

@app.route("/register",methods=["GET","POST"])
def register():
    if request.method=="GET":
        return render_template("register.html")
    else:
        identity=request.form.get("identity")
        password=request.form.get("password")
        password_encoded=password.encode()
        password_confirm=request.form.get("password-confirm")
        remember=True if request.form.get("remember") else False
        salt=secrets.token_hex(16)
        salt_encoded=salt.encode()
        verifier=hashlib.sha256((identity+password+salt).encode()).hexdigest()
        user=User.query.filter_by(identity=identity).first()
        if user:
            flash("That username allready exists!","danger")
            return render_template("register.html")
        elif password==password_confirm:
            new_user=User(identity=identity,verifier=verifier,salt=salt)
            database.session.add(new_user)
            database.session.commit()
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt_encoded,
                iterations=480000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password_encoded))
            session["_key"]=key
            login_user(new_user,remember=remember)
            return redirect(url_for("profile"))
        else:
            flash("Passwords do not match","danger")
            return render_template("register.html")

@app.route("/sign-in",methods=["GET","POST"])
def sign_in():
    if request.method=="GET":
        return render_template("sign-in.html")
    else:
        identity=request.form.get("identity")
        password=request.form.get("password")
        password_encoded = password.encode()
        remember=True if request.form.get("remember") else False
        user=User.query.filter_by(identity=identity).first()

        if not user:
            flash("Invalid username or password.","danger")
            return render_template("sign-in.html")
        
        salt=user.salt
        salt_encoded=salt.encode()
        verifier=hashlib.sha256((identity+password+salt).encode()).hexdigest()

        if user.verifier!=verifier:
            message=Markup("Invalid username or password. Reset password? <a href=\"{0}\">Reset</a>".format(url_for("reset_password")))
            flash(message,"danger")
            return render_template("sign-in.html")
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_encoded,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_encoded))
        session["_key"]=key

        login_user(user,remember=remember)
        return redirect(url_for("profile"))
    
@app.route("/reset-password",methods=["GET"])
def reset_password():
    message="There is no way to reset password!"
    flash(message,"danger")
    return redirect(url_for("sign_in"))
    
@app.route("/profile",methods=["GET"])
@login_required
def profile():
    return render_template("profile.html")

@app.route("/create",methods=["GET","POST"])
@login_required
def create():
    if request.method=="GET":
        return render_template("create.html")
    else:
        name=request.form.get("name")
        password=request.form.get("password")
        file_id=request.form.get("file-id")
        user=current_user
        key=session["_key"]
        fernet = Fernet(key)
        data=password.encode()
        token = fernet.encrypt(data)
        if file_id:
            file=UserFile.query.filter_by(id=file_id).first()
            file.data=token
            file.name=name
            message="Password updated successfully!"
        else:
            file=UserFile(data=token,name=name,user_id=user.id)
            message="Password added successfully!"
        database.session.add(file)
        database.session.commit()
        flash(message,"success")
        return redirect(url_for("profile"))

@app.route("/view",methods=["POST"])
@login_required
def view():
    file_id=request.form.get("file-id")
    key=session["_key"]
    fernet = Fernet(key)
    file=UserFile.query.filter_by(id=file_id).first()
    token=file.data
    data_encoded = fernet.decrypt(token)
    data=data_encoded.decode()
    name=file.name
    return render_template("view.html",name=name,data=data)

@app.route("/edit",methods=["POST"])
@login_required
def edit():
    file_id=request.form.get("file-id")
    key=session["_key"]
    fernet = Fernet(key)
    file=UserFile.query.filter_by(id=file_id).first()
    token=file.data
    data_encoded = fernet.decrypt(token)
    data=data_encoded.decode()
    name=file.name
    return render_template("edit.html",name=name,data=data,file_id=file_id)

@app.route("/delete",methods=["POST"])
@login_required
def delete():
    file_id=request.form.get("file-id")
    file=UserFile.query.filter_by(id=file_id).first()
    database.session.delete(file)
    database.session.commit()
    message="Entry deleted successfully!"
    flash(message,"success")
    return redirect(url_for("profile"))

@app.route("/change-password",methods=["GET","POST"])
@login_required
def change_password():
    if request.method=="GET":
        return render_template("change-password.html")
    else:
        password=request.form.get("password")
        new_password=request.form.get("password-new")
        new_password_confirm=request.form.get("password-new-confirm")
        user=current_user
        identity=user.identity
        salt=user.salt
        verifier=hashlib.sha256((identity+password+salt).encode()).hexdigest()

        if user.verifier!=verifier:
            message="Could not successfully change password!"
            flash(message,"danger")
            return redirect(url_for("profile"))
        elif new_password==new_password_confirm:
            new_password_encoded = new_password.encode()
            new_salt=secrets.token_hex(16)
            new_salt_encoded=new_salt.encode()
            # message="Invalid password!"
            # flash(message,"danger")
            new_kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=new_salt_encoded,
                iterations=480000,
            )

            key=session["_key"]
            new_key = base64.urlsafe_b64encode(new_kdf.derive(new_password_encoded))
            fernet = Fernet(key)
            new_fernet = Fernet(new_key)
            files=user.files
            for file in files:
                token=file.data
                data_encoded = fernet.decrypt(token)
                new_token=new_fernet.encrypt(data_encoded)
                file.data=new_token

            new_verifier=hashlib.sha256((identity+new_password+new_salt).encode()).hexdigest()
            user.verifier=new_verifier
            user.salt=new_salt
            database.session.commit()

            session["_key"]=new_key
            flash("Password successfully updated!","success")
        else:
            message="Could not successfully change password!"
            flash(message,"danger")
        return redirect(url_for("profile"))
    
@app.route("/delete-account",methods=["GET","POST"])
@login_required
def delete_account():
    if request.method=="GET":
        return render_template("delete-account.html")
    else:
        password=request.form.get("password")
        user=current_user
        user_id=current_user.id
        identity=user.identity
        salt=user.salt
        files=user.files
        verifier=hashlib.sha256((identity+password+salt).encode()).hexdigest()

        if user.verifier==verifier:
            for file in files:
                file_id=file.id
                delete_file=UserFile.query.filter_by(id=file_id).first()
                database.session.delete(delete_file)
            logout_user()
            delete_user=User.query.filter_by(id=user_id).first()
            database.session.delete(delete_user)
            database.session.commit()
            message="Your account has been successfully deleted!"
            flash(message,"success")
            return redirect(url_for("index"))
        else:
            message="Could not successfully delete account!"
            flash(message,"danger")
            return redirect(url_for("profile"))

@app.route("/sign-out",methods=["GET","POST"])
@login_required
def sign_out():
    logout_user()
    flash("You have been signed out!","success")
    return redirect(url_for("sign_in"))

if __name__=="__main__":
    # Create the database on first run
    with app.app_context():
        database.create_all()
    # Run the debug no matter what
    if DEBUG:
        app.run(host="0.0.0.0",port=443,debug=True,ssl_context="adhoc")
    elif DEVELOPMENT:
        app.run(host="0.0.0.0",port=443,debug=True,ssl_context="adhoc")
    elif SERVER:
        hostname=socket.gethostname()
        host=socket.gethostbyname(hostname)
        logger.info(hostname)
        logger.info(host)
        logger.info("Serving at https://"+host+":80")
        waitress.serve(app, host=host, port = 80, url_scheme = 'https')
    else:
        # Run application window
        webview.create_window('Password Manager', app)
        webview.start()