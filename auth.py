from flask import Flask, request, jsonify, make_response
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from config import app, db , mail
from database.models import *
from flask_mail import Message


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401
    
        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/signup', methods=['POST'])
def create_user():
    data = request.get_json()
    user_email = data.get('email')
    user_name = data.get("name")
    user_password = data.get("password")
    user = User.query.filter_by(email=user_email).first()
    print(user,"testing##############33 ")
    if user is None:
        hashed_password = generate_password_hash(user_password, method='sha256')
        new_user = User(public_id=str(uuid.uuid4()), name=user_name, password=hashed_password,email=user_email, admin=False)
        db.session.add(new_user)
        db.session.commit()

            # #######uuid#######
        uuids = str((uuid.uuid4))
       
        VerificationObject = EmailVerification(
                token=uuids,
                user = new_user
            )
        
        db.session.add(VerificationObject)   
        db.session.commit()

        
    ########email verification#######
        msg = Message(  
            'Verify your email address',                                         
        sender ='pythonteamdev@gmail.com',
            recipients = ["pulkitmadaanit@gmail.com"]                              
            )
        msg.body = f'http://127.0.0.1:5000/email_verification?token={uuids}'   
                                                                            
        mail.send(msg)    
    else:
        return jsonify({'message' : 'user already registred!'})
    return jsonify({'message' : 'New user created!'})



@app.route('/send_mail', methods=['POST'])
def send_email():
    msg = Message(  
            'Verify your email address',                                         
    sender ='pythonteamdev@gmail.com',
        recipients = ["pulkitmadaanit@gmail.com"]                              
        )
    msg.body = f'http://127.0.0.1:5000/email_verification?token={uuids}'   
                                                                        
    mail.send(msg)    

@app.route('/email_verification', methods=['POST'])

def verified_email():
   pass

@app.route('/login',methods=['POST'])
def login():
    auth = request.get_json()
    if not auth or not auth['email'] or not auth['password']:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(email=auth['email']).first()
    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth['password']):
        token = jwt.encode({'public_id' : user.public_id}, app.config['SECRET_KEY'])
        # token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token' : token})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})


if __name__ == '__main__':
    app.run(debug=True)
