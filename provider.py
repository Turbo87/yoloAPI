import time
from flask import request

from flask.ext.oauthlib.provider import OAuth2Provider
from oauthlib.oauth2.rfc6749.tokens import random_token_generator

import jwt


class MyProvider(OAuth2Provider):
    def init_app(self, app):
        super(MyProvider, self).init_app(app)
        app.config.setdefault('OAUTH2_PROVIDER_TOKEN_GENERATOR', self.generate_token)
        app.config.setdefault('OAUTH2_PROVIDER_REFRESH_TOKEN_GENERATOR', random_token_generator)

        self.secret = app.config.get('SECRET_KEY')

    def generate_token(self, request):
        token = {
            'user': request.user.id,
            'exp': int(time.time() + request.expires_in),
        }

        if request.scopes is not None:
            token['scope'] = ' '.join(request.scopes)

        return jwt.encode(token, self.secret)

    def verify_request(self, scopes):
        if request.authorization:
            from models import User

            user = User.find_with_password(
                request.authorization.username,
                request.authorization.password,
            )

            request.user_id = user.id if user else None
            return (user is not None), None

        else:
            valid, req = super(MyProvider, self).verify_request(scopes)

            request.user_id = req.access_token.user_id if valid else None

            return valid, req
