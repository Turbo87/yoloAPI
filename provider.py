from flask.ext.oauthlib.provider import OAuth2Provider


class MyProvider(OAuth2Provider):
    def init_app(self, app):
        super(MyProvider, self).init_app(app)
