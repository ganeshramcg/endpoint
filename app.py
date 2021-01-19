from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    jwt_refresh_token_required, create_refresh_token,
    get_jwt_identity, decode_token
)
import uuid
#import jwt
import datetime
from functools import wraps
from random import choice

app = Flask(__name__)
jwt = JWTManager(app)




app.config['SECRET_KEY']='Th1s1ss3cr3t'
app.config['SQLALCHEMY_DATABASE_URI']= r'sqlite:///C:\Users\Bittu\Desktop\flaskproject/library.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)



class Users(db.Model):
     id = db.Column(db.Integer, primary_key=True)
     public_id = db.Column(db.Integer)
     name = db.Column(db.String(50))
     password = db.Column(db.String(50))
     admin = db.Column(db.Boolean)


class TokenPool(db.Model):
      id = db.Column(db.Integer, primary_key=True)
      uniqueToken = db.Column(db.String(50))
      status_flag = db.Column(db.Boolean)


@app.route('/refreshToken', methods=['POST'])
@jwt_refresh_token_required
def refresh():
   current_user = get_jwt_identity()
   new_token = create_access_token(identity=current_user)
   return make_response({'New access token': new_token},200)
   



@app.route('/generateToken', methods=['GET'])
def GenerateToken():
   #new unique token
   new_token = str(uuid.uuid4())

   insert_new_token = TokenPool(uniqueToken = new_token, status_flag = False)
   db.session.add(insert_new_token)
   db.session.commit()
   return make_response({'message': 'New Token added to the pool'}, 200)


@app.route('/GetRandomToken', methods=['GET'])
def getRandomToken():
   all_tokens = TokenPool.query.filter_by(status_flag = False).all()
   if all_tokens:
      random_token = choice(all_tokens)
      random_token.status_flag = True
      db.session.commit()
      jwt_token = create_access_token(identity=random_token.uniqueToken, expires_delta=datetime.timedelta(seconds=60))
      refresh_token = create_refresh_token(identity=random_token.uniqueToken, expires_delta=datetime.timedelta(minutes=5))
      return make_response({'token': jwt_token, 'refresh_token': refresh_token}, 200)

   else: return make_response({'message': 'Tokens Unavailable'}, 400)

@app.route('/UnblockToken', methods=['GET'])
def unblocktoken():
   all_tokens = TokenPool.query.filter_by(status_flag = False).all()
   
   if not all_tokens:
      blocked_token = TokenPool.query.filter_by(status_flag = True).all()
      one_token = choice(blocked_token)
      one_token.status_flag = False
      db.session.commit()

      return make_response({'message': 'Token Unblocked. Request /GetRandomToken to get the token'}, 200)
   else:
      return make_response({'message': 'Tokens are available in the pool. Request /GetRandomToken to get the token'}, 403)


@app.route('/deleteToken', methods=['GET'])
def deleteToken():
   if 'x-access-tokens' in request.headers:
      header_token = request.headers['x-access-tokens']
      
      try:
         token = jwt.decode(header_token, app.config['SECRET_KEY'], algorithms='HS256')         
         res = TokenPool.query.filter_by(uniqueToken = token['token'])

         if res.delete() == 1:
            db.session.commit()
            return jsonify({'message': 'Your token has been removed successfully'})
         else: return jsonify({'message': 'Token doesn\'t exist'})

      except ValueError: return jsonify({'message': 'Invalid token'})

   else:
      return jsonify({'message': 'Token missing in header'})


@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
   token_data = get_jwt_identity()
   return make_response({'message': 'Token is still valid'})

def token_required(f):
   @wraps(f)
   def decorator(*args, **kwargs):

      token = None

      if 'x-access-tokens' in request.headers:
         token = request.headers['x-access-tokens']

      if not token:
         return jsonify({'message': 'a valid token is missing'})

      try:
         data = jwt.decode(token, app.config['SECRET_KEY'])
         current_user = Users.query.filter_by(public_id=data['public_id']).first()
      except:
         return jsonify({'message': 'token is invalid'})
      return f(current_user, *args, **kwargs)

   return decorator



@app.route('/register', methods=['GET', 'POST'])
def signup_user():

 data = request.get_json()  
 print(data)
 hashed_password = generate_password_hash(data['password'], method='sha256')
 
 new_user = Users(public_id=str(uuid.uuid4()), name=data['username'], password=hashed_password, admin=False) 
 db.session.add(new_user)  
 db.session.commit()    

 return jsonify({'message': 'registered successfully'})

@app.route('/login', methods=['GET', 'POST'])  
def login_user(): 
 
  auth = request.authorization   

  if not auth or not auth.username or not auth.password:  
     return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})    

  user = Users.query.filter_by(name=auth.username).first()   
     
  if check_password_hash(user.password, auth.password):  
     token = jwt.encode({'public_id': user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])  
     return jsonify({'token' : token.decode('UTF-8')}) 

  return make_response('could not verify',  401, {'WWW.Authentication': 'Basic realm: "login required"'})



if  __name__ == '__main__':  
     app.run(debug=True)