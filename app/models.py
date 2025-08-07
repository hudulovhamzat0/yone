from flask_login import UserMixin
from bson import ObjectId
from . import mongo

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.password = user_data['password']

    @staticmethod
    def get(user_id):
        try:
            user_data = mongo.db.users.find_one({"_id": ObjectId(user_id)})
            return User(user_data) if user_data else None
        except:
            return None

    @staticmethod
    def get_by_username(username):
        user_data = mongo.db.users.find_one({"username": username})
        return User(user_data) if user_data else None
