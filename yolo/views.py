#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask import Blueprint, request, jsonify

from yolo.oauth import oauth

api = Blueprint('api', __name__)


@api.route('/secrets')
@oauth.require_oauth()
def secrets():
    return jsonify({'secrets': [1, 1, 2, 3, 5, 8, 13]})


@api.route('/user')
@oauth.try_oauth()
def user():
    return jsonify({'user': request.user_id})
