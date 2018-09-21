import json
from datetime import datetime, timezone, timedelta
import hashlib
from flask import abort
from sqlalchemy import func, and_

from sociallogin import db, logger
from sociallogin.utils import b64encode_string, b64decode_string, \
    gen_jwt_token, decode_jwt
from sociallogin.atomic import generate_64bit_id


# Define a base model for other database tables to inherit
class Base(db.Model):
    __abstract__ = True

    _id = db.Column("id", db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    modified_at = db.Column(db.DateTime, default=db.func.current_timestamp(),
                            onupdate=db.func.current_timestamp())

    def __repr__(self):
        return str(self.as_dict())

    def as_dict(self):
        attrs = {}
        for k, v in self.__dict__.items():
            if k.startswith('_'):
                continue
            if isinstance(v, datetime):
                v = self.to_isoformat(v)
            attrs[k] = v
        return attrs

    @staticmethod
    def to_isoformat(dt):
        return dt.replace(tzinfo=timezone.utc).isoformat()


class Providers(Base):
    __tablename__ = 'providers'

    name = db.Column(db.String(15), nullable=False)
    version = db.Column(db.String(7), nullable=False)
    permissions = db.Column(db.String(1023), nullable=False)
    required_permissions = db.Column("permissions_required", db.String(1023), nullable=False)

    def __init__(self, name, version, permissions, required_permissions):
        self.name = name
        self.version = version
        self.permissions = permissions
        self.required_permissions = required_permissions

    @classmethod
    def init(cls):
        try:
            providers = [
                Providers(name='line', version='v2.1',
                          permissions='profile,openid,email',
                          required_permissions=''),
                Providers(name='amazon', version='v2',
                          permissions='profile,profile:user_id,postal_code',
                          required_permissions=''),
                Providers(name='yahoojp', version='v2',
                          permissions='profile,openid,email,address',
                          required_permissions='')
            ]
            db.session.bulk_save_objects(providers)
        except Exception as e:
            print(repr(e))
            pass


class Admins(Base):
    __tablename__ = 'admins'

    username = db.Column(db.String(32), nullable=False)
    email = db.Column(db.String(32), nullable=False)
    password = db.Column(db.String(64), nullable=False)
    salt = db.Column(db.String(16), nullable=False)
    phone = db.Column(db.String(16))


class Apps(Base):
    __tablename__ = 'apps'

    name = db.Column(db.String(63), nullable=False)
    api_key = db.Column(db.String(127), nullable=False)
    description = db.Unicode(db.Unicode(1023))
    allowed_ips = db.Column(db.String(255))
    callback_uris = db.Column(db.Text, nullable=False)

    owner_id = db.Column(db.Integer, db.ForeignKey("admins.id"), nullable=False)

    def __init__(self):
        super().__init__()
        self.is_authenticated = False
        self.is_active = True
        self.is_anonymous = False

    def get_id(self):
        return str(self._id)


class Channels(Base):
    __tablename__ = 'channels'

    provider = db.Column(db.String(15), nullable=False)
    client_id = db.Column(db.String(255), nullable=False)
    client_secret = db.Column(db.String(255), nullable=False)
    permissions = db.Column(db.String(1023), default='', nullable=False)

    app_id = db.Column(db.Integer, db.ForeignKey("apps.id"), nullable=False)


class SocialProfiles(Base):
    __tablename__ = 'social_profiles'

    provider = db.Column(db.String(15), nullable=False)
    pk = db.Column(db.String(40), unique=True, nullable=False)
    attrs = db.Column(db.Unicode(8191), nullable=False)
    last_authorized_at = db.Column("authorized_at", db.DateTime)
    login_count = db.Column(db.Integer, default=1, nullable=False)
    linked_at = db.Column(db.DateTime)
    _deleted = db.Column("deleted", db.Boolean, default=False)

    alias = db.Column(db.BigInteger, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    user_pk = db.Column(db.String(255))
    app_id = db.Column(db.Integer, db.ForeignKey("apps.id"), nullable=False)

    def __init__(self, app_id, pk, provider, attrs, last_authorized_at=datetime.now()):
        self.app_id = app_id
        self.pk = pk
        self.provider = provider
        self.attrs = json.dumps(attrs)
        self.last_authorized_at = last_authorized_at
        self.alias = generate_64bit_id()

    def as_dict(self):
        d = super().as_dict()
        d['attrs'] = json.loads(d['attrs'], encoding='utf8')
        d['social_id'] = self.alias
        d['user_id'] = d['user_pk']
        del d['user_pk']
        del d['alias']
        return d

    def link_user_by_id(self, user_id):
        try:
            _, pk = db.session.query(Users._id, Users.pk).filter_by(_id=user_id).one_or_none()
            self._link_unsafe(user_id, pk)
        except TypeError:
            abort(404, 'User not found')

    def link_user_by_pk(self, user_pk, create_if_not_exist=True):
        profiles = SocialProfiles.query.filter_by(app_id=self.app_id, user_pk=user_pk).all()
        if not profiles:
            user = Users.query.filter_by(app_id=self.app_id, pk=user_pk).one_or_none()
            if not user:
                if not create_if_not_exist:
                    abort(404, 'User not found')
                user = Users(pk=user_pk, app_id=self.app_id)
                db.session.add(user)
                db.session.flush()
            self._link_unsafe(user._id, user_pk)
        else:
            for p in profiles:
                if p.provider == self.provider:
                    abort(409, 'User linked with a social profile in the same provider')
            profile = profiles[0]
            self._link_unsafe(profile.user_id, user_pk, alias=profile.alias)

    def unlink_user_by_pk(self, user_pk):
        if self.user_pk != user_pk:
            abort(409, "Social profile and user don't linked with each other")
        self._unlink_unsafe()

    def _link_unsafe(self, user_id, user_pk, alias=None):
        self.user_id = user_id
        self.user_pk = user_pk
        self.linked_at = datetime.now()
        self.alias = alias or self.alias

    def _unlink_unsafe(self):
        self.linked_at = None
        self.user_id = None
        self.user_pk = None
        self.alias = generate_64bit_id()

    @classmethod
    def unlink_by_provider(cls, app_id, user_pk, providers):
        profiles = cls.query.filter_by(app_id=app_id, user_pk=user_pk).all()
        for p in profiles:
            if p.provider not in providers:
                continue
            p._unlink_unsafe()

    @classmethod
    def add_or_update(cls, app_id, pk, provider, attrs):
        hashpk = hashlib.sha1((provider + '.' + pk).encode('utf8')).hexdigest()
        profile = cls.query.filter_by(app_id=app_id, pk=hashpk).one_or_none()
        exists = True
        if not profile:
            profile = SocialProfiles(app_id=app_id, pk=hashpk, provider=provider, attrs=attrs)
            db.session.add(profile)
            db.session.flush()
            exists = False
        else:
            profile.last_authorized_at = datetime.now()
            profile.login_count += 1
            profile.attrs = json.dumps(attrs)
        return profile, exists


class Users(Base):
    __tablename__ = 'users'

    pk = db.Column(db.String(255), nullable=False)
    _deleted = db.Column("deleted", db.Boolean, default=False)
    app_id = db.Column(db.Integer, db.ForeignKey("apps.id"), nullable=False)

    def __init__(self, app_id, pk):
        self.app_id = app_id
        self.pk = pk

    def as_dict(self):
        d = super().as_dict()
        d['user_id'] = d['pk']
        del d['pk']
        return d

    @classmethod
    def get_full_as_dict(cls, app_id, pk):
        user = cls.query.filter_by(app_id=app_id, pk=pk).one_or_none()
        if user:
            profiles = SocialProfiles.query.filter_by(user_id=user._id).all()
            last_profile = None
            login_count = 0
            for p in profiles:
                login_count += p.login_count
                if not last_profile:
                    last_profile = p
                    continue
                if last_profile.last_authorized_at < p.last_authorized_at:
                    last_profile = p
            user_attrs = user.as_dict()
            user_attrs.update({
                'last_logged_in_provider': last_profile.provider,
                'last_logged_in_at': cls.to_isoformat(last_profile.last_authorized_at),
                'login_count': login_count
            })
            return {
                'user': user_attrs,
                'profiles': [p.as_dict() for p in profiles]
            }
        else:
            abort(404, 'User ID not found')


class Tokens(Base):
    __tablename__ = 'tokens'

    provider = db.Column(db.String(15), nullable=False)
    access_token = db.Column(db.String(2047), nullable=False)
    refresh_token = db.Column(db.String(2047))
    jwt_token = db.Column(db.String(2047))
    expires_at = db.Column(db.DateTime, nullable=False)
    token_type = db.Column(db.String(15))

    social_id = db.Column(db.Integer, db.ForeignKey('social_profiles.id'), nullable=False)

    def __init__(self, provider, access_token, expires_at, social_id,
                 refresh_token=None, jwt_token=None, token_type='Bearer'):
        self.provider = provider
        self.access_token = access_token
        self.expires_at = expires_at
        self.refresh_token = refresh_token
        self.jwt_token = jwt_token
        self.token_type = token_type
        self.social_id = social_id


class AuthLogs(Base):
    __tablename__ = 'auth_logs'

    STATUS_UNKNOWN = 'unknown'
    STATUS_AUTHORIZED = 'authorized'
    STATUS_SUCCEEDED = 'succeeded'
    STATUS_FAILED = 'failed'

    INTENT_AUTHENTICATE = 'authenticate'
    INTENT_ASSOCIATE = 'associate'
    INTENT_LOGIN = 'login'
    INTENT_REGISTER = 'register'

    ACTION_LOGIN = 1
    ACTION_REGISTER = 0

    provider = db.Column(db.String(15), nullable=False)
    callback_uri = db.Column(db.String(2047), nullable=False)
    callback_if_failed = db.Column("callback_failed", db.String(2047))
    nonce = db.Column(db.String(32), nullable=False)
    status = db.Column(db.String(15), nullable=False)
    is_login = db.Column(db.SmallInteger)
    auth_token = db.Column(db.String(32))
    ua = db.Column(db.String(4095))
    ip = db.Column(db.String(15))

    app_id = db.Column(db.Integer, db.ForeignKey("apps.id"), nullable=False)
    social_id = db.Column(db.Integer, db.ForeignKey('social_profiles.id'))

    def __init__(self, provider, app_id, nonce, callback_uri, callback_if_failed=None,
                 ua=None, ip=None, status=STATUS_UNKNOWN):
        self.provider = provider
        self.app_id = app_id
        self.nonce = nonce
        self.callback_uri = callback_uri
        self.callback_if_failed = callback_if_failed
        self.ua = ua
        self.ip = ip
        self.status = status

    def safe_get_failed_callback(self):
        return self.callback_if_failed or self.callback_uri

    def set_authorized(self, social_id, is_login, nonce):
        self.nonce = nonce
        self.social_id = social_id
        self.is_login = is_login
        self.status = self.STATUS_AUTHORIZED
        self.auth_token = self.generate_one_time_token()

    def generate_oauth_state(self, **kwargs):
        return gen_jwt_token(sub=self._id, exp_in_seconds=600,
                             _nonce=self.nonce, **kwargs)

    def generate_one_time_token(self):
        return self.nonce

    @classmethod
    def find_by_one_time_token(cls, auth_token):
        log = cls.query.filter_by(auth_token=auth_token).order_by(cls._id.desc()).first()
        if not log:
            abort(400, 'Invalid token')
        if log.status != AuthLogs.STATUS_AUTHORIZED:
            abort(400, 'Token expired or already used')
        return log

    @classmethod
    def parse_from_oauth_state(cls, oauth_state):
        try:
            log_id, args = decode_jwt(oauth_state)
            log = cls.query.filter_by(_id=log_id).one_or_none()
            if not log:
                abort(400, 'Invalid state')
            if log.nonce != args['_nonce']:
                abort(400, 'Invalid state, nonce does not match')
            return log, args
        except (KeyError, ValueError, TypeError, IndexError) as e:
            logger.warn('Bad format parameter OAuth state: %s', repr(e))
            abort(400, 'Bad format parameter OAuth state')
        except TimeoutError:
            abort(403, 'Session expired')


class AssociateLogs(Base):
    __tablename__ = 'associate_logs'

    STATUS_NEW = 'new'
    STATUS_AUTHORIZING = 'authorizing'
    STATUS_SUCCEEDED = 'succeeded'
    STATUS_FAILED = 'failed'

    provider = db.Column(db.String(15), nullable=False)
    status = db.Column(db.String(15), nullable=False)
    nonce = db.Column(db.String(32), nullable=False)

    app_id = db.Column(db.Integer, db.ForeignKey("apps.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __init__(self, provider, app_id, user_id, nonce, status=STATUS_NEW):
        self.provider = provider
        self.app_id = app_id
        self.user_id = user_id
        self.nonce = nonce
        self.status = status

    def generate_associate_token(self):
        return b64encode_string('{}.{}'.format(self.nonce, str(self.user_id)),
                                urlsafe=True, padding=False)

    @classmethod
    def add_or_reset(cls, provider, app_id, user_id, nonce):
        log = cls.query.filter_by(user_id=user_id, provider=provider).one_or_none()
        if log:
            log.status = cls.STATUS_NEW
            log.nonce = nonce
            log.provider = provider
        else:
            log = AssociateLogs(provider=provider, app_id=app_id,
                                user_id=user_id, nonce=nonce)
            db.session.add(log)
            db.session.flush()
        return log

    @classmethod
    def parse_from_associate_token(cls, associate_token):
        try:
            params = b64decode_string(associate_token, urlsafe=True).split('.')
            log = cls.query.filter_by(user_id=int(params[1])).order_by(cls._id.desc()).first()
            if not log:
                abort(400, 'Invalid associate token')
            if log.nonce != params[0]:
                abort(400, 'Invalid associate token, nonce does not match')
            if log.status != cls.STATUS_NEW:
                abort(400, 'Token expired or already used')
            return log
        except (KeyError, ValueError, TypeError, IndexError) as e:
            logger.warn('Bad format associate_token: %s', repr(e))
            abort(400, 'Bad format associate_token')
