import pytest
from werkzeug.datastructures import Headers

from yolo.app import create_app
from yolo.database import db as _db
from yolo.models import User

ORIGIN = 'https://www.google.com'


@pytest.fixture(scope='session')
def app():
    class TestConfig(object):
        TESTING = True
        SQLALCHEMY_DATABASE_URI = 'sqlite://'

    return create_app(settings_override=TestConfig)


@pytest.yield_fixture(scope='session')
def db(app):
    _db.app = app
    _db.create_all()
    yield _db
    _db.drop_all()


@pytest.fixture(scope='session')
def test_user(db):
    user = User(email_address='test@foo.com', password='secret123')
    db.session.add(user)
    db.session.commit()


@pytest.fixture
def tokens(client, test_user):
    headers = Headers()
    headers.set('Origin', ORIGIN)

    response = client.post('/oauth/token', headers=headers, data={
        'grant_type': 'password',
        'username': 'test@foo.com',
        'password': 'secret123',
    })
    assert response.status_code == 200
    assert response.headers.get('Access-Control-Allow-Origin') == ORIGIN
    assert response.headers.get('Access-Control-Allow-Credentials') == 'true'
    assert response.json.get('access_token')
    assert response.json.get('expires_in')
    assert response.json.get('token_type') == 'Bearer'
    assert response.json.get('refresh_token')

    return response.json


@pytest.fixture
def access_token(tokens):
    return tokens.get('access_token')


@pytest.fixture
def refresh_token(tokens):
    return tokens.get('refresh_token')
