#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask import Blueprint, render_template, request, jsonify
from models import User
from oauth import oauth

yoloapi = Blueprint('yoloApi', __name__)


@yoloapi.route('/oauth/token', methods=['POST'])
@oauth.token_handler
def access_token(*args, **kwargs):
    """ This endpoint is for exchanging/refreshing an access token.

    Returns a dictionary or None as the extra credentials for creating the
    token response.

    :param *args: Variable length argument list.
    :param **kwargs: Arbitrary keyword arguments.
    """
    return None


@yoloapi.route('/oauth/revoke', methods=['POST'])
@oauth.revoke_handler
def revoke_token():
    """ This endpoint allows a user to revoke their access token."""
    pass


@yoloapi.route('/', methods=['GET', 'POST'])
def management():
    """ This endpoint is for vieweing and adding users and clients. """
    if request.method == 'POST' and request.form['submit'] == 'Add User':
        User.save(request.form['username'], request.form['password'])
    return render_template('management.html', users=User.all())


@yoloapi.route('/secrets')
@oauth.require_oauth()
def secrets():
    return jsonify({'secrets': [1, 1, 2, 3, 5, 8, 13]})


@yoloapi.route('/user')
@oauth.try_oauth()
def user():
    return jsonify({'user': request.user_id})
