import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message


app = Flask(__name__)
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
database_path = APP_ROOT+'/bestorx.db'
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////'+database_path
db = SQLAlchemy(app)


###########################################################email################################
mail = Mail(app)

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'pythonteamdev@gmail.com'
app.config['MAIL_PASSWORD'] = 'Qwerty@123'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)    