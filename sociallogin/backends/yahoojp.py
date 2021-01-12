from sociallogin.backends import OAuthBackend


class YahooJpBackend(OAuthBackend):
    """
    Authentication handler for YAHOOJP accounts
    """
    OPENID_CONNECT_SUPPORT = True

    AUTHORIZE_URI = '''
               https://auth.login.yahoo.co.jp/yconnect/{version}/authorization?response_type=code
               &bail=1&display=page
               '''.strip().replace('\n', '').replace(' ', '')
    TOKEN_URI = 'https://auth.login.yahoo.co.jp/yconnect/{version}/token'
    PROFILE_URI = 'https://userinfo.yahooapis.jp/yconnect/{version}/attribute'
    IDENTIFY_ATTRS = ['sub']

    def _get_error(self, response, action):
        if action == 'get_profile':
            return 'api_error', response['Error']['Message']
        else:
            return super()._get_error(response, action)
