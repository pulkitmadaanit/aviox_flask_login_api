from config import db

class User(db.Model):
    # __tablename__ = 'User'
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
    is_verified = db.Column(db.Boolean)
    


class EmailVerification (db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(300), unique=True)  
    user = db.Column(db.Integer, db.ForeignKey('user.id'))
      
    # user = relationship("User", backref=backref("User", uselist=False))   

