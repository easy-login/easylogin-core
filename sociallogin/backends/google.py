import requests

from sociallogin import logger
from sociallogin.backends import OAuthBackend


class GoogleBackend(OAuthBackend):
    """
    Authentication handler for GOOGLE accounts
    """
    OPENID_CONNECT_SUPPORT = True

    AUTHORIZE_URI = '''
                https://accounts.google.com/o/oauth2/v2/auth?response_type=code
                &prompt=select_account&login_hint=sub&include_granted_scopes=true&access_type=offline
                '''.strip().replace('\n', '').replace(' ', '')
    TOKEN_URI = 'https://www.googleapis.com/oauth2/v4/token'
    VERIFY_TOKEN_URI = 'https://www.googleapis.com/oauth2/v3/tokeninfo'
    PROFILE_URI = 'https://people.googleapis.com/{version}/people/me'
    IDENTIFY_ATTRS = ['sub']

    def _get_profile(self, tokens):
        perms = self.channel.get_permissions()
        fields = self.channel.get_required_fields()
        if 'email' in perms and 'emailAddresses' not in fields:
            fields.append('emailAddresses')
        fields.remove('#')
        res = requests.get(self.__profile_uri__(version=self.channel.api_version), params={
            'personFields': ','.join(fields),
            'access_token': tokens['access_token']
        })
        if res.status_code != 200:
            body = res.json()
            logger.warn('Getting profile failed', style='hybrid',
                        provider=self.provider.upper(), **body)
            self._raise_error(
                error=self.ERROR_GET_PROFILE_FAILED,
                msg='Getting user attributes from provider failed')

        return self._get_attributes(response=res.json(), nofilter=True)

    def _get_attributes(self, response, nofilter=False):
        rs_name = response['resourceName']
        user_id = rs_name.split('/')[1]
        attrs = dict()
        for key, values in response.items():
            if type(values) != list:
                continue
            norm_values = [self._normalize_google_attribute(key, v) for v in values]
            attrs[key] = norm_values
        return user_id, attrs

    @staticmethod
    def _normalize_google_attribute(key, value):
        meta = value['metadata']
        value['source_type'] = meta['source']['type']
        if 'primary' in meta:
            value['primary'] = meta['primary']
        if 'verified' in meta:
            value['verified'] = meta['verified']
        if key == 'birthdays':
            date = value['date']
            if 'year' in date:
                value['date'] = '{}/{}/{}'.format(date['year'], date['month'], date['day'])
            else:
                value['date'] = '{}/{}'.format(date['month'], date['day'])
        del value['metadata']
        return value
