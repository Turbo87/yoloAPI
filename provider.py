import time

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
