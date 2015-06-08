#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask import Flask, jsonify, request
from validator import MyRequestValidator
from database import db
from oauth import oauth
from views import yoloapi


def create_app(settings_override=None):
    """ Method for creating and initializing application.

        :param settings_override: Dictionary of settings to override.
    """
    app = Flask(__name__)

    # Update configuration.
    app.config.from_object('settings')
    app.config.from_pyfile('settings.cfg', silent=True)
    app.config.from_object(settings_override)

    # Initialize extensions on the application.
    db.init_app(app)
    oauth.init_app(app)
    oauth._validator = MyRequestValidator()

    @oauth.invalid_response
    def invalid_require_oauth(req):
        message = req.error_message if req else 'Unauthorized'
        return jsonify(error='invalid_token', message=message), 401

    # Register views on the application.
    app.register_blueprint(yoloapi)

    @app.after_request
    def add_cors_headers(response):
        if 'Origin' in request.headers:
            response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin'))
            response.headers.add('Access-Control-Allow-Credentials', 'true')

            if 'Access-Control-Request-Methods' in request.headers:
                response.headers.add('Access-Control-Allow-Methods',
                                     request.headers.get('Access-Control-Request-Methods'))

            if 'Access-Control-Request-Headers' in request.headers:
                response.headers.add('Access-Control-Allow-Headers',
                                     request.headers.get('Access-Control-Request-Headers'))

        return response

    return app


if __name__ == '__main__':

    # Enable Flask-OAuthlib logging for this application.
    import logging
    logger = logging.getLogger('flask_oauthlib')
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)

    # Create app and SQL schemas in database, then run the application.
    app = create_app()
    db.create_all(app=app)
    app.run()
