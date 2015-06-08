#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask_oauthlib.provider import OAuth2RequestValidator
from flask_oauthlib.provider.oauth2 import log
from flask_oauthlib.utils import decode_base64
from oauthlib.common import to_unicode
from models import User, Client, Token


class MyRequestValidator(OAuth2RequestValidator):
    """ Defines a custom OAuth2 Request Validator based on the Client, User
        and Token models.

        :param OAuth2RequestValidator: Overrides the OAuth2RequestValidator.
    """
    def __init__(self):
        super(MyRequestValidator, self).__init__(
            clientgetter=lambda client_id: Client(),
            tokengetter=Token.find,
            grantgetter=None,
            usergetter=User.find_with_password,
            tokensetter=Token.save,
        )

    def rotate_refresh_token(self, request):
        return False

    def authenticate_client(self, request, *args, **kwargs):

        auth = request.headers.get('Authorization', None)
        if auth:
            try:
                _, s = auth.split(' ')
                client_id, client_secret = decode_base64(s).split(':')
                client_id = to_unicode(client_id, 'utf-8')
            except Exception as e:
                log.debug('Authenticate client failed with exception: %r', e)
                return False
        else:
            client_id = request.client_id

        client = self._clientgetter(client_id)
        if not client:
            log.debug('Authenticate client failed, client not found.')
            return False

        return self.authenticate_client_id(client_id, request)
