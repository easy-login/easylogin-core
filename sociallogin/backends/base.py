import urllib.parse as up
from datetime import datetime, timedelta
from typing import List

import requests
from flask import request, url_for, redirect, jsonify

from sociallogin import db, logger
from sociallogin.exc import RedirectLoginError, PermissionDeniedError, \
    NotFoundError, BadRequestError, TokenParseError
from sociallogin.models import Apps, Channels, AuthLogs, Tokens, \
    SocialProfiles, JournalLogs, AssociateLogs
from sociallogin.utils import gen_random_token, add_params_to_uri, \
    smart_str2bool, get_remote_ip, update_dict


class OAuthBackend(object):
    OAUTH_VERSION = 2
    SANDBOX_SUPPORT = False
    OPENID_CONNECT_SUPPORT = False

    AUTHORIZE_URI: str = None
    TOKEN_URI: str = None
    VERIFY_TOKEN_URI: str = None
    PROFILE_URI: str = None
    IDENTIFY_ATTRS: List = []

    ERROR_AUTHORIZE_FAILED = 'authorize_failed'
    ERROR_GET_TOKEN_FAILED = 'get_token_failed'
    ERROR_GET_PROFILE_FAILED = 'get_profile_failed'

    def __init__(self, provider):
        self.provider = provider
        self.sandbox = False
        self.platform = None

        self.channel = None
        self.log = None
        self.token = None
        self.profile = None
        self.args = None

    def verify_callback_success(self, params):
        if self.OAUTH_VERSION == 2:
            return 'code' in params
        else:
            return 'oauth_token' in params and 'oauth_verifier' in params

    def authorize(self, app_id, intent, succ_callback, fail_callback, params):
        """

        :param app_id:
        :param intent:
        :param succ_callback:
        :param fail_callback:
        :param params:
        :return:
        """
        # Verify request params and extract extra args
        self._init_authorize(intent=intent, params=params)

        app = Apps.query.filter_by(_id=app_id, _deleted=0).one_or_none()
        self.channel = Channels.query.filter_by(app_id=app_id,
                                                provider=self.provider).one_or_none()
        if not app or not self.channel:
            raise NotFoundError(msg='Application or channel not found')

        if not self._is_mobile():
            allowed_uris = [up.unquote_plus(uri) for uri in app.get_callback_uris()]
            logger.debug('Verify callback URI', style='hybrid', allowed_uris=allowed_uris,
                         succ_callback=succ_callback, fail_callback=fail_callback)

            illegal_callback_msg = ('Invalid callback_uri value. '
                                    'Check if it is registered in EasyLogin developer site')
            if not self.verify_callback_uri(allowed_uris, succ_callback):
                raise PermissionDeniedError(msg=illegal_callback_msg)
            if fail_callback and not self.verify_callback_uri(allowed_uris, fail_callback):
                raise PermissionDeniedError(msg=illegal_callback_msg)

        self.log = AuthLogs(
            provider=self.provider,
            app_id=app_id,
            nonce=gen_random_token(nbytes=32),
            intent=intent,
            platform=self.platform,
            callback_uri=succ_callback,
            callback_if_failed=fail_callback
        )
        db.session.add(self.log)
        db.session.flush()
        db.session.add(JournalLogs(
            ua=request.headers.get('User-Agent'),
            ip=get_remote_ip(request),
            path=request.full_path,
            ref_id=self.log._id
        ))

        oauth_state = self.log.generate_oauth_state(**self.args)
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

    def _init_authorize(self, intent, params):
        self.sandbox = smart_str2bool(params.get('sandbox'))
        if self.sandbox:
            self._enable_sandbox()

        nonce = params.get('nonce', '')
        if len(nonce) > 255:
            raise BadRequestError('Nonce length exceeded limit 255 characters')

        self.platform = params.get('platform', 'web')
        if self.platform not in ['web', 'ios', 'and']:
            raise BadRequestError('Invalid or unsupported platform')

        self.args = {
            'sandbox': self.sandbox,
            'platform': self.platform,
            'nonce': nonce
        }
        if self._is_mobile():
            code_challenge = params.get('code_challenge', '')
            if not code_challenge:
                raise BadRequestError('Missing required parameter code_challenge for mobile client')
            if len(code_challenge) > 128:
                raise BadRequestError('Malformed parameter: code_challenge')
            self.args['code_challenge'] = code_challenge

        if intent == AuthLogs.INTENT_ASSOCIATE:
            assoc_token = params.get('associate_token', '')
            try:
                alog = AssociateLogs.parse_associate_token(assoc_token)
                if alog.provider != self.provider:
                    raise BadRequestError('Invalid target provider, must be {}'.format(alog.provider))

                alog.status = AssociateLogs.STATUS_AUTHORIZING
                update_dict(self.args, dst_social_id=alog.dst_social_id, provider=self.provider)
            except TokenParseError as e:
                logger.warning('Parse associate token failed',
                               error=e.description, token=assoc_token)
                raise BadRequestError('Invalid associate token')
        elif intent == AuthLogs.INTENT_PAY_WITH_AMAZON:
            update_dict(self.args, lpwa_domain=params.get('site_domain'))

    def _is_mobile(self):
        return self.platform != 'web'

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

    def handle_authorize_error(self, state, params):
        """

        :param state:
        :param params:
        :return:
        """
        self.log, self.args = self.verify_and_parse_state(state)
        self.log.status = AuthLogs.STATUS_FAILED
        if self.log.provider != self.provider:
            raise PermissionDeniedError('OAuth state invalid, provider does not match',
                                        provider=self.log.provider, expected=self.provider)

        error, desc = self._get_error(params, action='authorize')
        logger.debug('Authorize failed', provider=self.provider.upper(),
                     error=error, message=desc)
        self._raise_error(error=self.ERROR_AUTHORIZE_FAILED,
                          msg='{}, {}'.format(error, desc))

    def handle_authorize_success(self, state, params):
        """

        :param state:
        :param params:
        :return:
        """
        self.log, self.args = self.verify_and_parse_state(state)
        if self.log.provider != self.provider:
            logger.warn('Provider in OAuth state does not match with current provider',
                        provider=self.log.provider, expected=self.provider)
            raise PermissionDeniedError('OAuth state invalid, provider does not match')

        if self.args.get('sandbox'):
            self._enable_sandbox()
        self.platform = self.args.get('platform')
        logger.debug('Parse OAuth state result', sub=self.log._id, **self.args)

        self.channel = Channels.query.filter_by(app_id=self.log.app_id,
                                                provider=self.provider).one_or_none()
        try:
            self.profile, self.token = self._handle_authentication(params)
        except Exception:
            self.log.status = AuthLogs.STATUS_FAILED
            db.session.commit()
            raise

        intent = self.log.intent
        if intent == AuthLogs.INTENT_ASSOCIATE:
            if self.args.get('provider') != self.provider:
                self._raise_error(error='permission_denied',
                                  msg='Target provider does not match')
            elif self.profile.user_id:
                self._raise_error(error='conflict',
                                  msg='Profile has linked with another user')
            self.profile.merge_with(alias=self.args.get('dst_social_id'))
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
            auth_token = self.log.generate_auth_token(
                code_challenge=self.args.get('code_challenge'))
            return jsonify({
                'auth_token': auth_token,
                'expires_in': 3900
            })
        else:
            auth_token = self.log.generate_auth_token()
            callback_uri = add_params_to_uri(
                uri=self.log.callback_uri,
                provider=self.provider,
                token=auth_token,
                nonce=self.args.get('nonce', '')
            )
            return self._make_redirect_response(callback_uri=callback_uri)

    def _handle_authentication(self, params):
        """

        :param params:
        :return:
        """
        if self._is_mobile():
            access_token = params['access_token']
            id_token = params.get('id_token')
            tokens = self._debug_token(access_token=access_token, id_token=id_token)
        else:
            code = params['code']
            tokens = self._get_token(code=code)
        user_id, attrs = self._get_profile(tokens=tokens)

        profile, existed = SocialProfiles.add_or_update(
            app_id=self.log.app_id,
            provider=self.provider,
            scope_id=user_id, attrs=attrs)
        self.log.set_authorized(social_id=profile._id, is_login=existed,
                                nonce=gen_random_token(nbytes=32))
        token = Tokens(
            provider=self.provider,
            access_token=tokens['access_token'],
            token_type=tokens['token_type'],
            expires_at=datetime.utcnow() + timedelta(seconds=tokens['expires_in']),
            refresh_token=tokens.get('refresh_token'),
            id_token=tokens.get('id_token'),
            social_id=profile._id
        )
        db.session.add(token)
        return profile, token

    def _enable_sandbox(self):
        if self.SANDBOX_SUPPORT:
            self.sandbox = True
            logger.info('Enable sandbox mode', provider=self.provider)
        else:
            logger.warn('Cannot enable sandbox mode, provider is not supported',
                        provider=self.provider)

    def _get_token(self, code):
        """

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
        return res.json()

    def _debug_token(self, access_token, id_token=None):
        """

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
        return {
            'access_token': access_token,
            'expires_in': token_info['expires_in'],
            'token_type': 'Bearer',
            'id_token': id_token
        }

    def _get_profile(self, tokens):
        """

        :param tokens:
        :return:
        """
        authorization = tokens['token_type'] + ' ' + tokens['access_token']
        res = requests.get(self.__profile_uri__(version=self.channel.api_version),
                           headers={'Authorization': authorization})
        if res.status_code != 200:
            body = res.json()
            logger.warn('Getting profile failed', style='hybrid',
                        provider=self.provider.upper(), **body)
            self._raise_error(
                error=self.ERROR_GET_PROFILE_FAILED,
                msg='Getting user attributes from provider failed')

        return self._get_attributes(response=res.json())

    def _get_attributes(self, response, nofilter=False):
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

    def _make_redirect_response(self, callback_uri):
        """
        Make response redirect to client callback URI
        :param callback_uri:
        :return:
        """
        return redirect(callback_uri)

    def _get_error(self, response, action):
        return response['error'], response.get('error_description', '')

    def _raise_error(self, error, msg):
        if self._is_mobile():
            return jsonify({
                'error': error,
                'error_description': msg,
                'provider': self.provider
            })
        else:
            raise RedirectLoginError(
                error=error, msg=msg,
                nonce=self.args.get('nonce', ''),
                redirect_uri=self.log.get_failed_callback(),
                provider=self.provider)

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
        return url_for('authorize_callback', _external=True, _scheme='https', provider=self.provider)

    @staticmethod
    def verify_and_parse_state(state):
        try:
            return AuthLogs.parse_oauth_state(oauth_state=state)
        except TokenParseError as e:
            logger.warning('Parse OAuth state failed', error=e.description, token=state)
            raise BadRequestError('Invalid OAuth state')

    @staticmethod
    def verify_callback_uri(allowed_uris, uri):
        if not uri:
            return False
        r1 = up.urlparse(uri)
        # Always allow callback for hosted JS
        if r1.netloc == 'api.easy-login.jp' \
                and r1.path == '/hosted/auth/callback' \
                and r1.scheme == 'https':
            return True

        for _uri in allowed_uris:
            r2 = up.urlparse(_uri)
            ok = r1.scheme == r2.scheme and r1.netloc == r2.netloc and r1.path == r2.path
            if ok:
                return True
        return False

    @staticmethod
    def extract_domain_for_cookie(url, subdomain=True):
        netloc = up.urlparse(url).netloc
        if netloc.startswith('localhost'):
            return None
        else:
            parts = netloc.split('.')
            domain = parts[-2] + '.' + parts[-1]
            if subdomain:
                domain = '.' + domain
            return domain
