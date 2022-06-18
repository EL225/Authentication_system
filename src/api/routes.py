"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager


api = Blueprint('api', __name__)


@api.route('/signup', methods=['POST'])
def handle_Signup():
    
    email= request.json.get("email", None)
    password = request.json.get("password", None)

    if not email or not password:
        return jsonify({"msg": "Es mecesaro el correo y password"}), 404

    user_new = User(email=email, password=password, is_active=True)
    db.session.add(user_new)
    db.session.commit()

    response_body = {
        "msg": "usuario creado correctamente" 
    }

    return jsonify(response_body), 200

@api.route('/login', methods=['POST'])
def handle_Login():
    
    email= request.json.get("email", None)
    password = request.json.get("password", None)

    email_query = User.query.filter_by(email=email, password=password).first()
    #print(email_query.name)

    if not email_query:
        return jsonify({"msg": "usuario o password incorrecto"}), 404

    print(email_query.id)
    
    #password_query = User.query.filter_by(password=password)

    response_body = {
        "msg": "bienvenido de vuelta" 
    }

    return jsonify(response_body), 200