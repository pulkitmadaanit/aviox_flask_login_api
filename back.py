from flask import Flask, request, jsonify, make_response
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from config import app, db ,mail
from database.models import *

##################################
from flask_mail import Mail, Message


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
   
    if request.method == 'POST':
        user_email = request.form['email']
        user = User.query.filter_by(email=user_email).first()
        #return user is already register
        if not user:
            user = User(
                    email=request.form['email'],
                    password=request.form['password'],
                    name= request.form['name'],
                )
                # insert the user
            db.session.add(user)
            db.session.commit()
            # uuid
            uuids = str(uuid.uuid4()) 
            uuidd = EmailVerification(
                    token=uuids
                )
            db.session.add(uuidd)   
            db.session.commit()
            #email verification

            msg = Message(  
              'Verify your email address',                                          # heading verify your email address
            sender ='pythonteamdev@gmail.com',
                recipients = [request.form['email']]                              # post requesst se jo email aayegi
                )
            msg.body = f'http://127.0.0.1:5000/signup/{uuids}'   
                                                                              #token value
            msg.body = 'http://127.0.0.1:5000/signup/{}'.format(uuids)   
            mail.send(msg)                                                     # message delivered

        #send token 
    else:
        pass
    # send a messsage already registered
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password,email=data['email'], admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New user created!'})



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





#user data aayega post request se 
#sabse phele user db mein check karna padega, agar ha to "user already exists"
# nahi ha to uska emailaddress verify karwana padega,
# token jayega email pr, verify karte hi user details store in database    
