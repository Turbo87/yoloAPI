from flask.ext.oauthlib.provider import OAuth2Provider
from oauthlib.oauth2.rfc6749.tokens import random_token_generator


class MyProvider(OAuth2Provider):
    def init_app(self, app):
        super(MyProvider, self).init_app(app)
        app.config.setdefault('OAUTH2_PROVIDER_TOKEN_GENERATOR', random_token_generator)
        app.config.setdefault('OAUTH2_PROVIDER_REFRESH_TOKEN_GENERATOR', random_token_generator)
