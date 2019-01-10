import requests


class Response:

    def __init__(self, r):
        self.response = r
        self.text = r.text
        self.status_code = r.status_code
        self.success = self.response.status_code in [200, 201]
        self.failed = not self.success

    def json(self):
        return self.response.json()


class BaseApiClient:

    def _send_get(self, url, params):
        return self._send_request(method='get', url=url, params=params)

    def _send_post(self, url, params):
        return self._send_request(method='post', url=url, params=params)

    def _send_put(self, url, params):
        return self._send_request(method='put', url=url, params=params)

    def _send_delete(self, url, params):
        return self._send_request(method='delete', url=url, params=params)

    def _send_request(self, method, url, params):
        raise NotImplementedError()


class EasyLoginClient(BaseApiClient):
    BASE_URL = 'https://api.easy-login.jp'
    BASE_USER_URL = BASE_URL + '/{}/users'

    AUTHORIZED_PROFILE_URL = BASE_URL + '/{}/profiles/authorized'
    ACTIVATE_PROFILE_URL = BASE_URL + '/{}/profiles/'
    LINK_PROFILE_URL = BASE_URL + '/{}/users/link'
    UNLINK_PROFILE_URL = BASE_URL + '/{}/users/unlink'
    MERGE_USER_URL = BASE_URL + '/{}/users/merge'
    DISASSOCIATE_PROVIDER_URL = BASE_URL + '/{}/users/disassociate'
    DELETE_USER_INFO_URL = BASE_URL + '/{}/users/reset'
    CREATE_ASSOCIATE_TOKEN_URL = BASE_URL + '/{}/users/associate-token'

    def __init__(self, app_id, api_key):
        self.app_id = app_id
        self.api_key = api_key

    def get_authorized_profile(self, access_token):
        params = {'token': access_token}
        url = self.AUTHORIZED_PROFILE_URL.format(self.app_id)
        return self._send_post(url=url, params=params)

    def activate_profile(self, access_token):
        params = {'token': access_token}
        url = self.ACTIVATE_PROFILE_URL.format(self.app_id)
        return self._send_post(url=url, params=params)

    def link_social_profile_with_user(self, social_id, user_id):
        params = {'social_id': social_id, 'user_id': user_id}
        url = self.LINK_PROFILE_URL.format(self.app_id)
        return self._send_put(url=url, params=params)

    def unlink_social_profile_from_user(self, social_id, user_id):
        pass

    def merge_user(self, src_social_id=None, src_user_id=None,
                   dst_social_id=None, dst_user_id=None):
        params = {
            'src_social_id': src_social_id,
            'dst_social_id': dst_social_id,
            'src_user_id': src_user_id,
            'dst_user_id': dst_user_id
        }
        url = self.MERGE_USER_URL.format(self.app_id)
        return self._send_put(url=url, params=params)

    def get_user_profile(self, social_id=None, user_id=None):
        params = {'social_id': social_id, 'user_id': user_id}
        url = self.BASE_USER_URL.format(self.app_id)
        return self._send_get(url=url, params=params)

    def _send_request(self, method, url, params):
        headers = {'X-Api-Key': self.api_key}
        method = method.upper()
        print(method, url, params)
        if method == 'GET':
            r = requests.get(url=url, params=params, headers=headers, verify=False)
        elif method == 'POST':
            r = requests.post(url=url, json=params, headers=headers, verify=False)
        elif method == 'PUT':
            r = requests.put(url=url, json=params, headers=headers, verify=False)
        elif method == 'DELETE':
            r = requests.delete(url=url, json=params, headers=headers, verify=False)
        else:
            raise ValueError('Invalid or unsupported method')
        return Response(r)


class ShopifyClient(BaseApiClient):

    def __init__(self, store_url, access_token):
        self.access_token = access_token
        self.base_url = 'https://{}/admin'.format(store_url)

    def get_shop_info(self):
        url = self.base_url + '/shop.json'
        return self._send_get(url=url, params={'fields': 'id'})

    def search_customer(self, query, fields='id'):
        qs = ' '.join(['{}:{}'.format(k, v) for k, v in query.items()])
        url = self.base_url + '/customers/search.json'
        return self._send_get(url=url, params={'query': query, 'fields': fields})

    def update_customer(self, customer_id, customer):
        url = self.base_url + '/customers/{}.json'.format(customer_id)
        return self._send_put(url=url, params={'customer': customer})

    def create_customer(self, customer):
        url = self.base_url + '/customers.json'
        return self._send_post(url=url, params={'customer': customer})

    def search_script_tag(self, src, fields='id'):
        url = self.base_url + '/script_tags.json'
        return self._send_get(url=url, params={'src': src, 'fields': fields})

    def create_script_tag(self, src, display_scope='all'):
        url = self.base_url + '/script_tags.json'
        script_tag = {
            'src': src,
            'display_scope': display_scope,
            'event': 'onload'
        }
        return self._send_post(url=url, params={'script_tag': script_tag})

    def _send_request(self, method, url, params):
        method = method.upper()
        print(method, url, params)
        if method == 'GET':
            r = requests.get(url=url, params=params,
                             headers={'X-Shopify-Access-Token': self.access_token})
        elif method == 'POST':
            r = requests.post(url=url, json=params,
                              headers={'X-Shopify-Access-Token': self.access_token})
        elif method == 'PUT':
            r = requests.put(url=url, json=params,
                             headers={'X-Shopify-Access-Token': self.access_token})
        elif method == 'DELETE':
            r = requests.delete(url=url, json=params,
                                headers={'X-Shopify-Access-Token': self.access_token})
        else:
            raise ValueError('Invalid or unsupported method')
        return Response(r)
