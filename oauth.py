from flask import Blueprint

from provider import CustomProvider
from validator import CustomRequestValidator

oauth = CustomProvider()
oauth._validator = CustomRequestValidator()
oauth.blueprint = Blueprint('oauth', __name__)


@oauth.blueprint.route('/oauth/token', methods=['POST'])
@oauth.token_handler
def access_token(*args, **kwargs):
    return None


@oauth.blueprint.route('/oauth/revoke', methods=['POST'])
@oauth.revoke_handler
def revoke_token():
    pass
