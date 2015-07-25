#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask import Blueprint, render_template, request, jsonify

from yolo.models import User
from yolo.oauth import oauth

yoloapi = Blueprint('yoloApi', __name__)


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
