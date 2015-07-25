import pytest
from werkzeug.datastructures import Headers

from yolo.app import create_app

ORIGIN = 'https://www.google.com'


@pytest.fixture(scope='session')
def app():
    return create_app(settings_override={'TESTING': True})


@pytest.fixture
def tokens(client):
    headers = Headers()
    headers.set('Origin', ORIGIN)

    response = client.post('/oauth/token', headers=headers, data={
        'grant_type': 'password',
        'username': 'test',
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
