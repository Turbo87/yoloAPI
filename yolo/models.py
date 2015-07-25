#!/usr/bin/env python
# -*- coding: utf-8 -*-

from datetime import datetime
from flask import current_app
import jwt

import bcrypt

from yolo.database import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True)
    hashpw = db.Column(db.String(80))

    @staticmethod
    def find_with_password(username, password, *args, **kwargs):
        """ Query the User collection for a record with matching username and password hash. """
        user = User.query.filter_by(username=username).first()
        if not user:
            return None

        encodedpw = password.encode('utf-8')
        userhash = user.hashpw.encode('utf-8')

        return user if user.hashpw == bcrypt.hashpw(encodedpw, userhash) else None

    @staticmethod
    def save(username, password):
        """ Create a new User record with the supplied username and password. """
        salt = bcrypt.gensalt()
        hash = bcrypt.hashpw(password.encode('utf-8'), salt)
        user = User(username=username, hashpw=hash)
        db.session.add(user)
        db.session.commit()

    @staticmethod
    def all():
        """ Return all User records found in the database. """
        return User.query.all()


class Client(object):
    client_id = 'default'
    client_secret = None
    client_type = 'public'
    redirect_uris = []
    default_redirect_uri = ''
    default_scopes = []
    allowed_grant_types = ['password', 'refresh_token']


class AccessToken(object):
    client_id = Client.client_id
    token_type = 'Bearer'
    user = None

    @classmethod
    def from_jwt(cls, access_token):
        try:
            decoded = jwt.decode(access_token, current_app.config.get('SECRET_KEY'),
                                 options={'verify_exp': False})
        except jwt.InvalidTokenError:
            return None

        return AccessToken(
            access_token,
            user_id=decoded['user'],
            expires=datetime.utcfromtimestamp(decoded['exp'])
        )

    def __init__(self, access_token, user_id, expires, scopes=None):
        self.access_token = access_token
        self.user_id = user_id
        self.expires = expires
        self.scopes = scopes or []


class RefreshToken(db.Model):
    __tablename__ = 'token'

    id = db.Column(db.Integer, primary_key=True)
    client_id = Client.client_id
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User')
    refresh_token = db.Column(db.String(255), unique=True)
    scopes = []

    def delete(self):
        db.session.delete(self)
        db.session.commit()
