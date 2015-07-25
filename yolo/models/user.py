import bcrypt

from yolo.database import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True)
    hashpw = db.Column(db.String(80))

    @staticmethod
    def find_with_password(username, password, *args, **kwargs):
        """ Query the User collection for a record with matching username and password hash. """
        user = User.query.filter_by(username=username).first()
        if not user:
            return None

        encodedpw = password.encode('utf-8')
        userhash = user.hashpw.encode('utf-8')

        return user if user.hashpw == bcrypt.hashpw(encodedpw, userhash) else None

    @staticmethod
    def save(username, password):
        """ Create a new User record with the supplied username and password. """
        salt = bcrypt.gensalt()
        hash = bcrypt.hashpw(password.encode('utf-8'), salt)
        user = User(username=username, hashpw=hash)
        db.session.add(user)
        db.session.commit()
