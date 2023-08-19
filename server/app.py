#!/usr/bin/env python3

from flask import request, session, make_response, abort
from flask_restful import Resource

from config import app, db, api, bcrypt
from models import User

class ClearSession(Resource):

    def delete(self):
    
        session['page_views'] = None
        session['user_id'] = None

        return {}, 204

class Signup(Resource):
    
    def post(self):
        json_data = request.get_json()

        new_user = User(username=json_data['username'])
        new_user._password_hash = json_data['password']

        db.session.add(new_user)
        db.session.commit()
        
        response = make_response(
            new_user.to_dict(), 
            201
        )

        return response

class CheckSession(Resource):
    def get(self):
        user_id = session['user_id']

        if user_id:
            user = User.query.filter(User.id == user_id).first()
            return user.to_dict()
            
        return {}, 204

class Login(Resource):
    def post(self):
        try:
            username = request.get_json().get('username')
            user = User.query.filter_by(username=username).first()
            if user:
                session['user_id'] = user.id
                response = make_response(
                    user.to_dict(),
                    200
                )
                return response
        except:
            abort(401, "Incorrect Username or Password")


class Logout(Resource):
    def delete(self):
        session['user_id'] = None

        return {}, 204

api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
