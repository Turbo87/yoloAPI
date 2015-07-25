from flask import Blueprint

from provider import MyProvider
from validator import MyRequestValidator

oauth = MyProvider()
oauth._validator = MyRequestValidator()
oauth.blueprint = Blueprint('oauth', __name__)


@oauth.blueprint.route('/oauth/token', methods=['POST'])
@oauth.token_handler
def access_token(*args, **kwargs):
    return None


@oauth.blueprint.route('/oauth/revoke', methods=['POST'])
@oauth.revoke_handler
def revoke_token():
    pass
