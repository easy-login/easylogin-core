import urllib.parse as up
from datetime import datetime, timedelta
from typing import List, Tuple, Dict, Any, Optional

import requests
from flask import request, url_for, redirect, jsonify

from sociallogin import app, db, logger
from sociallogin.backends.utils import verify_callback_uri, generate_oauth_state, parse_associate_token, \
    generate_auth_token
from sociallogin.constants import PLATFORM_WEB, ALL_PLATFORMS
from sociallogin.entities import OAuthAuthorizeParams, OAuthCallbackParams, \
    OAuthSessionParams, OAuth2TokenPack
from sociallogin.exc import RedirectLoginError, PermissionDeniedError, \
    NotFoundError, BadRequestError, TokenParseError
from sociallogin.models import Apps, Channels, AuthLogs, Tokens, \
    SocialProfiles, JournalLogs, AssociateLogs
from sociallogin.sec import jwt_token_service as jwt_token_svc
from sociallogin.utils import gen_random_token, add_params_to_uri, get_remote_ip


class OAuthBackend(object):
    OAUTH_VERSION = 2
    SANDBOX_SUPPORT = False
    OPENID_CONNECT_SUPPORT = False

    AUTHORIZE_URI: str
    TOKEN_URI: str
    VERIFY_TOKEN_URI: str
    PROFILE_URI: str
    IDENTIFY_ATTRS: List[str] = []

    ERROR_AUTHORIZE_FAILED = 'authorize_failed'
    ERROR_GET_TOKEN_FAILED = 'get_token_failed'
    ERROR_GET_PROFILE_FAILED = 'get_profile_failed'

    def __init__(self, provider):
        self.provider = provider
        self.channel: Optional[Channels] = None
        self.log: Optional[AuthLogs] = None
        self.session: Optional[OAuthSessionParams] = None

    def verify_callback_success(self, params):
        if self.OAUTH_VERSION == 2:
            return 'code' in params
        else:
            return 'oauth_token' in params and 'oauth_verifier' in params

    def authorize(self, params: OAuthAuthorizeParams):
        # Verify request params and extract session data
        self.session = self._verify_and_parse_session(params=params)

        oauth_app = Apps.query.filter_by(_id=params.app_id, _deleted=0).one_or_none()
        self.channel = Channels.query.filter_by(app_id=params.app_id,
                                                provider=self.provider).one_or_none()
        if not oauth_app or not self.channel:
            raise NotFoundError(msg='Application or channel not found')

        if not self._is_mobile():
            allowed_uris = [up.unquote_plus(uri) for uri in oauth_app.get_callback_uris()]
            logger.debug('Verify callback URI',
                         style='hybrid', allowed_uris=allowed_uris,
                         succ_callback=params.success_callback,
                         fail_callback=params.failed_callback)

            illegal_callback_msg = ('Invalid callback_uri value. '
                                    'Check if it is registered in EasyLogin developer site')

            if not verify_callback_uri(allowed_uris, params.success_callback):
                raise PermissionDeniedError(msg=illegal_callback_msg)

            if params.failed_callback and not verify_callback_uri(allowed_uris, params.failed_callback):
                raise PermissionDeniedError(msg=illegal_callback_msg)

        self.log = AuthLogs(
            provider=self.provider,
            app_id=params.app_id,
            nonce=gen_random_token(nbytes=32),
            intent=params.intent,
            platform=self.session.platform,
            callback_uri=params.success_callback,
            callback_if_failed=params.failed_callback
        )
        db.session.add(self.log)
        db.session.flush()
        db.session.add(JournalLogs(
            ua=request.headers.get('User-Agent'),
            ip=get_remote_ip(request),
            path=request.full_path,
            ref_id=self.log._id
        ))

        oauth_state = generate_oauth_state(self.log, **self.session.to_dict())
        if self._is_mobile():
            return jsonify({
                'channel': {
                    'client_id': self.channel.client_id,
                    'options': self.channel.get_options(),
                    'scopes': self.channel.get_permissions()
                },
                'state': oauth_state
            })
        else:
            url = self._build_authorize_uri(state=oauth_state)
            logger.debug('Authorize URL', url)
            return redirect(url)

    def _verify_and_parse_session(self, params: OAuthAuthorizeParams) -> OAuthSessionParams:
        nonce = params.nonce
        if len(nonce) > 255:
            raise BadRequestError('Nonce length exceeded limit 255 characters')

        platform = params.platform or PLATFORM_WEB
        if platform not in ALL_PLATFORMS:
            raise BadRequestError('Invalid or unsupported platform')

        session_data = {
            'provider': self.provider,
            'sandbox': params.sandbox,
            'platform': platform,
            'nonce': nonce
        }
        if self._is_mobile():
            code_challenge = params.code_challenge
            if not code_challenge:
                raise BadRequestError('Missing required parameter code_challenge for mobile client')
            if len(code_challenge) > 128:
                raise BadRequestError('Malformed parameter: code_challenge')
            session_data['code_challenge'] = code_challenge

        if params.intent == AuthLogs.INTENT_ASSOCIATE:
            assoc_token = params.associate_token
            try:
                alog = parse_associate_token(assoc_token)
                if alog.provider != self.provider:
                    raise BadRequestError('Invalid target provider, must be {}'.format(alog.provider))

                alog.status = AssociateLogs.STATUS_AUTHORIZING
                session_data['dst_social_id'] = alog.dst_social_id
            except TokenParseError as e:
                logger.warning('Parse associate token failed',
                               error=e.description, token=assoc_token)
                raise BadRequestError('Invalid associate token')
        elif params.intent == AuthLogs.INTENT_PAY_WITH_AMAZON:
            session_data['lpwa_domain'] = params.site_domain

        return OAuthSessionParams(data=session_data)

    def _build_authorize_uri(self, state):
        """

        :param state:
        :return:
        """
        uri = add_params_to_uri(
            uri=self.__authorize_uri__(version=self.channel.api_version),
            client_id=self.channel.client_id,
            redirect_uri=self.__provider_callback_uri__(),
            scope=up.unquote_plus(self.channel.get_perms_as_oauth_scope()),
            state=state)
        if self.OPENID_CONNECT_SUPPORT:
            uri += '&nonce=' + gen_random_token(nbytes=16, format='hex')
        return uri

    def handle_authorize_error(self, params: OAuthCallbackParams):
        self.log, self.session = self._parse_oauth_state(params.state)
        self.log.status = AuthLogs.STATUS_FAILED
        logger.debug('Parse OAuth state result', sub=self.log._id, **self.session.to_dict())

        error, desc = self._get_error(params.to_dict(), action='authorize')
        logger.debug('Authorize with provider failed',
                     provider=self.provider.upper(), error=error, message=desc)

        error_data = {
            'error': self.ERROR_AUTHORIZE_FAILED,
            'msg': '{}, {}'.format(error, desc),
            'nonce': self.session.nonce,
            'provider': self.provider
        }
        if self.log.callback_if_failed:
            redirect_url = add_params_to_uri(uri=self.log.callback_if_failed, **error_data)
            return redirect(redirect_url)
        else:
            return jsonify(error_data)

    def handle_authorize_success(self, params: OAuthCallbackParams):
        self.log, self.session = self._parse_oauth_state(state=params.state)
        logger.debug('Parse OAuth state result', sub=self.log._id, **self.session.to_dict())

        try:
            self.channel = Channels.query.filter_by(app_id=self.log.app_id,
                                                    provider=self.provider).one_or_none()
            profile, token = self._handle_authentication(params=params)
        except Exception:
            self.log.status = AuthLogs.STATUS_FAILED
            db.session.commit()
            raise

        intent = self.log.intent
        if intent == AuthLogs.INTENT_ASSOCIATE:
            if self.session.provider != self.provider:
                self._raise_error(error='permission_denied',
                                  msg='Target provider does not match')
            elif profile.user_id:
                self._raise_error(error='conflict',
                                  msg='Profile has linked with another user')
            profile.merge_with(alias=self.session.dst_social_id)
        elif intent == AuthLogs.INTENT_LOGIN and not self.log.is_login:
            self._raise_error(
                error='invalid_request',
                msg='Social profile does not exist, should register instead'
            )
        elif intent == AuthLogs.INTENT_REGISTER and self.log.is_login:
            self._raise_error(
                error='invalid_request',
                msg='Social profile already existed, should login instead'
            )

        if self._is_mobile():
            return self._make_mobile_authorize_success_response(token)
        else:
            return self._make_web_authorize_success_response(token)

    def _parse_oauth_state(self, state: str) -> Tuple[AuthLogs, OAuthSessionParams]:
        try:
            log_id, args = jwt_token_svc.decode(token=state)
            log: Optional[AuthLogs] = AuthLogs.query.filter_by(_id=log_id).one_or_none()

            if not log or log.nonce != args.get('_nonce'):
                logger.debug('Invalid OAuth state or nonce does not match')
                raise BadRequestError('Invalid OAuth state')

            if log.status != AuthLogs.STATUS_UNKNOWN:
                logger.debug('Validate OAuth state failed. Illegal auth log status.',
                             status=log.status, expected=AuthLogs.STATUS_UNKNOWN)
                raise BadRequestError('Invalid OAuth state')

            if log.provider != self.provider:
                logger.warn('Provider in OAuth state does not match with current provider',
                            provider=log.provider, expected=self.provider)
                raise PermissionDeniedError('OAuth state invalid, provider does not match')

            return log, OAuthSessionParams(data=args)
        except TokenParseError as e:
            logger.warning('Parse OAuth state failed', error=e.description, token=state)
            raise BadRequestError('Invalid OAuth state')

    def _make_mobile_authorize_success_response(self, _: Tokens):
        auth_token = generate_auth_token(self.log, code_challenge=self.session.code_challenge)
        return jsonify({
            'auth_token': auth_token,
            'expires_in': 3600
        })

    def _make_web_authorize_success_response(self, _: Tokens):
        auth_token = generate_auth_token(self.log)
        callback_uri = add_params_to_uri(
            uri=self.log.callback_uri,
            provider=self.provider,
            token=auth_token,
            nonce=self.session.nonce
        )
        return redirect(callback_uri)

    def _handle_authentication(self, params: OAuthCallbackParams) -> Tuple[SocialProfiles, Tokens]:
        """
        Handle authentication, return authenticated profile + token info
        :param params:
        :return:
        """
        if self._is_mobile():
            access_token = params.access_token
            id_token = params.id_token
            token_pack = self._debug_token(access_token=access_token, id_token=id_token)
        else:
            code = params.code
            token_pack: OAuth2TokenPack = self._get_token(code=code)
        user_id, attrs = self._get_profile(token_pack=token_pack)

        profile, existed = SocialProfiles.add_or_update(
            app_id=self.log.app_id,
            provider=self.provider,
            scope_id=user_id, attrs=attrs)
        self.log.set_authorized(social_id=profile._id, is_login=existed,
                                nonce=gen_random_token(nbytes=32))
        token = Tokens(
            provider=self.provider,
            access_token=token_pack.access_token,
            token_type=token_pack.token_type,
            expires_at=datetime.utcnow() + timedelta(seconds=token_pack.expires_in),
            refresh_token=token_pack.refresh_token,
            id_token=token_pack.id_token,
            social_id=profile._id
        )
        db.session.add(token)
        return profile, token

    def _get_token(self, code) -> OAuth2TokenPack:
        """
        Get OAuth2 access token by authorization code
        :param code:
        :return:
        """
        res = requests.post(self.__token_uri__(version=self.channel.api_version), data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.__provider_callback_uri__(),
            'client_id': self.channel.client_id,
            'client_secret': self.channel.client_secret
        })
        if res.status_code != 200:
            body = res.json()
            error, desc = self._get_error(body, action='get_token')
            logger.warn('Getting access token failed', style='hybrid',
                        provider=self.provider.upper(), **body)
            self._raise_error(error=self.ERROR_GET_TOKEN_FAILED,
                              msg='{}: {}'.format(error, desc))
        return OAuth2TokenPack(data=res.json())

    def _debug_token(self, access_token, id_token=None) -> OAuth2TokenPack:
        """
        Debug adnd get access token that was sent by Mobile SDK
        :param access_token:
        :return:
        """
        res = requests.get(self.__verify_token_uri(version=self.channel.api_version),
                           params={'access_token': access_token})
        if res.status_code != 200:
            body = res.json()
            error, desc = self._get_error(body, action='get_token')
            logger.warn('Verify access token failed', style='hybrid',
                        provider=self.provider.upper(), **body)
            self._raise_error(error=self.ERROR_GET_TOKEN_FAILED,
                              msg='{}: {}'.format(error, desc))
        token_info = res.json()
        client_id = token_info['client_id']
        if client_id != self.channel.client_id:
            logger.warn('Access token does not belong to current app',
                        client_id=client_id, expected=self.channel.client_id)
            raise PermissionDeniedError('Illegal access token')

        return OAuth2TokenPack(
            access_token=access_token,
            expires_in=token_info['expires_in'],
            token_type='Bearer',
            id_token=id_token
        )

    def _get_profile(self, token_pack: OAuth2TokenPack) -> Tuple[str, Dict[str, Any]]:
        """
        Get profile attributes of authenticated profile
        :param token_pack:
        :return:
        """
        authorization = token_pack.token_type + ' ' + token_pack.access_token
        res = requests.get(self.__profile_uri__(version=self.channel.api_version),
                           headers={'Authorization': authorization})
        if res.status_code != 200:
            body = res.json()
            logger.warn('Getting profile failed', style='hybrid',
                        provider=self.provider.upper(), **body)
            self._raise_error(
                error=self.ERROR_GET_PROFILE_FAILED,
                msg='Getting user attributes from provider failed')

        return self._parse_attributes(response=res.json())

    def _parse_attributes(self, response: Dict[str, Any], nofilter=False) -> Tuple[str, Dict[str, Any]]:
        """

        :param response:
        :param nofilter:
        :return:
        """
        user_id = response[self.__identify_attrs__()[0]]
        if nofilter or self.channel.option_enabled(key='extra_fields'):
            for key in self.__identify_attrs__():
                del response[key]
            return user_id, response

        attrs = dict()
        fields = self.channel.get_required_fields()
        for key, value in response.items():
            if key in fields:
                attrs[key] = value
        return user_id, attrs

    def _get_error(self, response, action):
        return response['error'], response.get('error_description', '')

    def _raise_error(self, error: str, msg: str):
        if self._is_mobile():
            return jsonify({
                'error': error,
                'error_description': msg,
                'provider': self.provider
            })
        else:
            raise RedirectLoginError(
                error=error, msg=msg,
                nonce=self.session.nonce,
                redirect_uri=self.log.get_failed_callback(),
                provider=self.provider)

    def _is_mobile(self):
        return self.session.platform != PLATFORM_WEB

    def __identify_attrs__(self):
        return self.IDENTIFY_ATTRS

    def __authorize_uri__(self, version, numeric_format=False):
        if version and numeric_format:
            version = version.replace('v', '')
        return self.AUTHORIZE_URI.format(version=version)

    def __token_uri__(self, version, numeric_format=False):
        if version and numeric_format:
            version = version.replace('v', '')
        return self.TOKEN_URI.format(version=version)

    def __verify_token_uri(self, version, numeric_format=False):
        if version and numeric_format:
            version = version.replace('v', '')
        return self.VERIFY_TOKEN_URI.format(version=version)

    def __profile_uri__(self, version, numeric_format=False):
        if version and numeric_format:
            version = version.replace('v', '')
        return self.PROFILE_URI.format(version=version)

    def __provider_callback_uri__(self):
        return url_for('authorize_callback', _external=True, provider=self.provider,
                       _scheme='http' if app.config['DEBUG'] else 'https')
