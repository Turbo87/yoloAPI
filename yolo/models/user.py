import os
from hashlib import sha256

from sqlalchemy.ext.hybrid import hybrid_property

from yolo.database import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email_address = db.Column(db.Unicode(255), unique=True)
    _password = db.Column('password', db.Unicode(128), nullable=False)

    @staticmethod
    def by_email_address(email):
        """Return the user object whose email address is ``email``."""
        return User.query.filter_by(email_address=email).first()

    @staticmethod
    def by_credentials(email, password, *args, **kwargs):
        """
        Return the user object whose email address is ``email`` if the
        password is matching.
        """
        user = User.by_email_address(email)
        if user and user.validate_password(password):
            return user

    @hybrid_property
    def password(self):
        """Return the hashed version of the password."""
        return self._password

    @password.setter
    def password(self, password):
        """Hash ``password`` on the fly and store its hashed version."""
        self._password = self._hash_password(password)

    @classmethod
    def _hash_password(cls, password):
        # Make sure password is a str because we cannot hash unicode objects
        if isinstance(password, unicode):
            password = password.encode('utf-8')
        salt = sha256()
        salt.update(os.urandom(60))
        hash = sha256()
        hash.update(password + salt.hexdigest())
        password = salt.hexdigest() + hash.hexdigest()
        # Make sure the hashed password is a unicode object at the end of the
        # process because SQLAlchemy _wants_ unicode objects for Unicode cols
        if not isinstance(password, unicode):
            password = password.decode('utf-8')
        return password

    def validate_password(self, password):
        """
        Check the password against existing credentials.

        :param password: the password that was provided by the user to
            try and authenticate. This is the clear text version that we will
            need to match against the hashed one in the database.
        :type password: unicode object.
        :return: Whether the password is valid.
        :rtype: bool

        """

        # Make sure accounts without a password can't log in
        if not self.password or not password:
            return False

        hash = sha256()
        if isinstance(password, unicode):
            password = password.encode('utf-8')
        hash.update(password + str(self.password[:64]))
        return self.password[64:] == hash.hexdigest()
