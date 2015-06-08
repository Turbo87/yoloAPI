#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
The core module holds generic functions and the Flask extensions.
"""

from flask_sqlalchemy import SQLAlchemy
from provider import MyProvider

db = SQLAlchemy()
oauth = MyProvider()
