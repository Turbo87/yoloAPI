from functools import wraps
import time
from flask import request, abort

from flask.ext.oauthlib.provider import OAuth2Provider
from oauthlib.oauth2.rfc6749.tokens import random_token_generator

import jwt


class CustomProvider(OAuth2Provider):
    def init_app(self, app):
        super(CustomProvider, self).init_app(app)
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
            valid, req = super(CustomProvider, self).verify_request(scopes)

            request.user_id = req.access_token.user_id if valid else None

            return valid, req

    def try_oauth(self, *scopes):
        """Enhance resource with specified scopes."""
        def wrapper(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                for func in self._before_request_funcs:
                    func()

                if hasattr(request, 'oauth') and request.oauth:
                    return f(*args, **kwargs)

                valid, req = self.verify_request(scopes)

                for func in self._after_request_funcs:
                    valid, req = func(valid, req)

                if not valid and (not req or 'Authorization' in req.headers or req.access_token):
                    if self._invalid_response:
                        return self._invalid_response(req)
                    return abort(401)
                request.oauth = req
                return f(*args, **kwargs)
            return decorated
        return wrapper
