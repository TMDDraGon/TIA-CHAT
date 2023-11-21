from flask_login import UserMixin
from sqlalchemy_serializer import SerializerMixin
from app import db
             
class AuthUser(db.Model, UserMixin):
    __tablename__ = "auth_users"
    # primary keys are required by SQLAlchemy
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    name = db.Column(db.String(1000))
    password = db.Column(db.String(100))
    avatar_url = db.Column(db.String(200))
    check = db.Column(db.String(200))

    def __init__(self, email, name, password, avatar_url, check):
        self.email = email
        self.name = name
        self.password = password
        self.avatar_url = avatar_url
        self.check = check
        
    def updateuser(self, name, email):
        self.name = name
        self.email = email

    def updateprofile(self, avatar_url):
        self.avatar_url = avatar_url
