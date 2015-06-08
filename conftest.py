import pytest

from app import create_app


@pytest.fixture
def app():
    return create_app(settings_override={'TESTING': True})


@pytest.fixture
def tokens(client):
    response = client.post('/oauth/token', data={
        'grant_type': 'password',
        'username': 'test',
        'password': 'secret123',
    })
    assert response.status_code == 200
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
