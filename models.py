#!/usr/bin/env python
# -*- coding: utf-8 -*-

from datetime import datetime
from flask import current_app
import jwt

from database import db
import bcrypt


class User(db.Model):
    """ User which will be querying resources from the API.

    :param db.Model: Base class for database models.
    """

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True)
    hashpw = db.Column(db.String(80))

    @staticmethod
    def find_with_password(username, password, *args, **kwargs):
        """ Query the User collection for a record with matching username and
        password hash.

        :param username: Username of the user.
        :param password: Password of the user.
        :param *args: Variable length argument list.
        :param **kwargs: Arbitrary keyword arguments.
        """
        user = User.query.filter_by(username=username).first()
        if not user:
            return None

        encodedpw = password.encode('utf-8')
        userhash = user.hashpw.encode('utf-8')

        return user if user.hashpw == bcrypt.hashpw(encodedpw, userhash) else None

    @staticmethod
    def save(username, password):
        """ Create a new User record with the supplied username and password.

        :param username: Username of the user.
        :param password: Password of the user.
        """
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
    """ Client application through which user is authenticating.

    RFC 6749 Section 2 (http://tools.ietf.org/html/rfc6749#section-2)
    describes clients:

    +----------+
     | Resource |
     |  Owner   |
     |          |
     +----------+
          v
          |    Resource Owner
         (A) Password Credentials
          |
          v
     +---------+                                  +---------------+
     |         |>--(B)---- Resource Owner ------->|               |
     |         |         Password Credentials     | Authorization |
     | Client  |                                  |     Server    |
     |         |<--(C)---- Access Token ---------<|               |
     |         |    (w/ Optional Refresh Token)   |               |
     +---------+                                  +---------------+

    Redirection URIs are mandatory for clients. We skip this requirement
    as this example only allows the resource owner password credentials
    grant (described in Section 4.3). In this flow, the Authorization
    Server will not redirect the user as described in subsection 3.1.2
    (Redirection Endpoint).

    :param db.Model: Base class for database models.
    """
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
    """ Access or refresh token

        Because of our current grant flow, we are able to associate tokens
        with the users who are requesting them. This can be used to track usage
        and potential abuse. Only bearer tokens currently supported.

        :param db.Model: Base class for database models.
    """
    id = db.Column(db.Integer, primary_key=True)
    client_id = Client.client_id
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User')
    refresh_token = db.Column(db.String(255), unique=True)
    scopes = []

    def delete(self):
        db.session.delete(self)
        db.session.commit()
