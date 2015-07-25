#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask_oauthlib.provider import OAuth2RequestValidator
from flask_oauthlib.provider.oauth2 import log
from flask_oauthlib.utils import decode_base64
from oauthlib.common import to_unicode

from database import db
from models import User, Client, RefreshToken, AccessToken


class CustomRequestValidator(OAuth2RequestValidator):
    """ Defines a custom OAuth2 Request Validator based on the Client, User
        and Token models.

        :param OAuth2RequestValidator: Overrides the OAuth2RequestValidator.
    """
    def __init__(self):
        super(CustomRequestValidator, self).__init__(
            clientgetter=lambda client_id: Client(),
            tokengetter=self.tokengetter,
            grantgetter=None,
            usergetter=User.find_with_password,
            tokensetter=self.tokensetter,
        )

    @staticmethod
    def tokengetter(access_token=None, refresh_token=None):
        """ Retrieve a token record using submitted access token or
        refresh token.

        :param access_token: User access token.
        :param refresh_token: User refresh token.
        """
        if access_token:
            return AccessToken.from_jwt(access_token)

        elif refresh_token:
            return RefreshToken.query.filter_by(refresh_token=refresh_token).first()

    @staticmethod
    def tokensetter(token, request, *args, **kwargs):
        """ Save a new token to the database.

        :param token: Token dictionary containing access and refresh tokens,
            plus token type.
        :param request: Request dictionary containing information about the
            client and user.
        """

        if not request.grant_type == 'refresh_token':
            tok = RefreshToken(
                refresh_token=token['refresh_token'],
                user_id=request.user.id,
            )
            db.session.add(tok)
            db.session.commit()

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
