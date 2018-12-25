import hashlib
import json
import time
from datetime import datetime, timedelta

from sqlalchemy import func, and_
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.sql import expression
from sqlalchemy.types import DateTime

from sociallogin import db, logger, app
from sociallogin.atomic import generate_64bit_id
from sociallogin.exc import ConflictError, NotFoundError, BadRequestError
from sociallogin.sec import jwt_token_service as jwts, easy_token_service as ests
from sociallogin.utils import gen_random_token, convert_to_user_timezone


class utcnow(expression.FunctionElement):
    type = DateTime()


@compiles(utcnow, 'postgresql')
def pg_utcnow(element, compiler, **kw):
    return "TIMEZONE('utc', CURRENT_TIMESTAMP)"


@compiles(utcnow, 'mssql')
def ms_utcnow(element, compiler, **kw):
    return "GETUTCDATE()"


@compiles(utcnow, 'mysql')
def my_utcnow(element, compiler, **kw):
    return "UTC_TIMESTAMP()"


# Define a base model for other database tables to inherit
class Base(db.Model):
    __abstract__ = True

    HIDDEN_FIELDS = set()

    _id = db.Column("id", db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=utcnow())
    modified_at = db.Column(db.DateTime, default=utcnow(), onupdate=utcnow())

    def __repr__(self):
        return json.dumps(self.as_dict(), indent=2)

    def __id__(self):
        return str(self._id)

    def as_dict(self):
        attrs = {}
        for k, v in self.__dict__.items():
            if k.startswith('_') or k in self.HIDDEN_FIELDS:
                continue
            if isinstance(v, datetime):
                v = self.to_isoformat(v)
            attrs[k] = v
        return attrs

    @staticmethod
    def to_isoformat(dt):
        return convert_to_user_timezone(dt).isoformat()


class Providers(Base):
    __tablename__ = 'providers'

    name = db.Column(db.String(15), nullable=False)
    version = db.Column(db.String(15), nullable=False)
    required_permissions = db.Column(db.String(1023), nullable=False)
    basic_fields = db.Column(db.String(4095), nullable=False)
    advanced_fields = db.Column(db.String(4095), nullable=False)
    options = db.Column(db.String(1023))


class SystemSettings(Base):
    __tablename__ = 'system_settings'

    _last_update_ = datetime.now()
    _cache_ = dict()

    name = db.Column(db.String(32), nullable=False)
    value = db.Column(db.String(64), nullable=False)

    @classmethod
    def all_as_dict(cls):
        # keep cache in 10 minutes, only in production mode
        if app.config['DEBUG']:
            rows = cls.query.all()
            return {e.name: e.value for e in rows}
        else:
            now = datetime.now()
            if not cls._cache_ or cls._last_update_ + timedelta(minutes=10) < now:
                logger.info('Refresh System settings cache',
                            current_size=len(cls._cache_), last_update=cls._last_update_)
                rows = cls.query.all()
                cls._cache_ = {e.name: e.value for e in rows}
                cls._last_update_ = now
            return cls._cache_


class Admins(Base):
    __tablename__ = 'admins'

    LEVEL_NORMAL = 0
    LEVEL_PREMIUM = 1
    LEVEL_LINE_PLUS = 2
    LEVEL_AMAZON_PLUS = 3

    username = db.Column(db.String(32), nullable=False)
    email = db.Column(db.String(32), nullable=False)
    password = db.Column(db.String(64), nullable=False)
    is_superuser = db.Column(db.SmallInteger, nullable=False, default=0)
    level = db.Column(db.SmallInteger, nullable=False, default=0)


class Apps(Base):
    __tablename__ = 'apps'

    name = db.Column(db.String(255), nullable=False)
    api_key = db.Column(db.String(64), nullable=False)
    allowed_ips = db.Column(db.String(255))
    callback_uris = db.Column(db.Text, nullable=False)
    options = db.Column(db.String(255))

    _deleted = db.Column("deleted", db.SmallInteger, nullable=False, default=0)
    owner_id = db.Column(db.Integer, db.ForeignKey("admins.id"), nullable=False)

    def __init__(self):
        super().__init__()
        self.is_authenticated = False
        self.is_active = True
        self.is_anonymous = False

    def get_callback_uris(self):
        return self.callback_uris.split('|')

    def get_options(self):
        return (self.options or '').split('|')

    def option_enabled(self, key):
        return key in self.get_options()


class Channels(Base):
    __tablename__ = 'channels'

    provider = db.Column(db.String(15), nullable=False)
    api_version = db.Column(db.String(15), nullable=False)
    client_id = db.Column(db.String(255), nullable=False)
    client_secret = db.Column(db.String(255), nullable=False)
    permissions = db.Column(db.String(1023), nullable=False)
    required_fields = db.Column(db.String(1023), nullable=False)
    options = db.Column(db.String(255))

    app_id = db.Column(db.Integer, db.ForeignKey("apps.id"), nullable=False)

    def get_permissions(self):
        return (self.permissions or '').split('|')

    def get_perms_as_oauth_scope(self):
        return (self.permissions or '').replace('|', ' ')

    def get_required_fields(self):
        return (self.required_fields or '').split('|')

    def get_options(self):
        return (self.options or '').split('|')

    def option_enabled(self, key):
        return key in self.get_options()


class SocialProfiles(Base):
    __tablename__ = 'social_profiles'

    HIDDEN_FIELDS = {
        'pk', 'scope_id', 'alias', 'user_id', 'user_pk', 'app_id'
    }

    provider = db.Column(db.String(15), nullable=False)
    pk = db.Column(db.String(40), unique=True, nullable=False)
    attrs = db.Column(db.Unicode(8191), nullable=False)
    scope_id = db.Column(db.String(255), nullable=False)
    last_authorized_at = db.Column("authorized_at", db.DateTime)
    login_count = db.Column(db.Integer, default=0, nullable=False)
    verified = db.Column(db.SmallInteger, default=0, nullable=False)
    _deleted = db.Column("deleted", db.SmallInteger, default=0)
    linked_at = db.Column(db.DateTime)
    alias = db.Column(db.BigInteger, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    user_pk = db.Column(db.String(128))
    app_id = db.Column(db.Integer, db.ForeignKey("apps.id"), nullable=False)

    def __init__(self, *args, **kwargs):
        self.app_id = kwargs['app_id']
        self.provider = kwargs['provider']
        self.attrs = json.dumps(kwargs['attrs'])
        self.last_authorized_at = datetime.utcnow()
        self.alias = generate_64bit_id(shard=self.app_id)
        self.scope_id = kwargs['scope_id']
        self.pk = kwargs['pk']

    def as_dict(self):
        d = super().as_dict()
        d['attrs'] = json.loads(self.attrs, encoding='utf8')
        d['social_id'] = str(self.alias)
        d['user_id'] = self.user_pk
        d['verified'] = bool(self.verified)
        if self._allow_get_scope_id():
            # d['attrs']['id'] = self.scope_id
            d['scope_id'] = self.scope_id
        return d

    @classmethod
    def link_user_by_pk(cls, app_id, social_id, user_pk, create_if_not_exist=True):
        profiles = SocialProfiles.query.filter_by(alias=social_id).all()
        if not profiles:
            raise NotFoundError('Social ID not found')
        if profiles[0].user_id:
            raise ConflictError('Unacceptable operation. '
                                'Social profile has linked with an exists user')
        num_user_same_pk = (db.session.query(func.count(SocialProfiles._id))
            .join(Users, and_(Users._id == SocialProfiles.user_id,
                              Users.pk == user_pk, Users.app_id == app_id))
            .scalar())
        if num_user_same_pk > 0:
            raise ConflictError('User has linked with another social profile')
            
        user = Users.query.filter_by(pk=user_pk, app_id=app_id).one_or_none()
        if not user:
            if not create_if_not_exist:
                raise NotFoundError('User not found')
            user = Users(pk=user_pk, app_id=app_id)
            db.session.add(user)
            db.session.flush()
        for p in profiles:
            p._link_unsafe(user._id, user_pk)

    def link_user_by_id(self, user_id):
        try:
            _, pk = db.session.query(Users._id, Users.pk).filter_by(_id=user_id).one_or_none()
            self._link_unsafe(user_id, pk)
        except TypeError:
            raise NotFoundError('User not found')

    def _link_user_by_pk(self, user_pk, create_if_not_exist=True):
        profiles = SocialProfiles.query.filter_by(user_pk=user_pk, app_id=self.app_id).all()
        if not profiles:
            user = Users.query.filter_by(pk=user_pk, app_id=self.app_id).one_or_none()
            if not user:
                if not create_if_not_exist:
                    raise NotFoundError('User not found')
                user = Users(pk=user_pk, app_id=self.app_id)
                db.session.add(user)
                db.session.flush()
            self._link_unsafe(user._id, user_pk)
        else:
            for p in profiles:
                if p.provider == self.provider:
                    raise ConflictError('User has linked with a social profile in the same provider')
            profile = profiles[0]
            self._link_unsafe(profile.user_id, user_pk)

    @classmethod
    def unlink_user_by_pk(cls, app_id, social_id, user_pk):
        user = Users.query.filter_by(pk=user_pk, app_id=app_id).one_or_none()
        if not user:
            raise NotFoundError('User ID not found')
        return cls.query.filter_by(alias=social_id, user_id=user._id).update({
            'linked_at': None,
            'user_id': None
        }, synchronize_session=False)

    def _unlink_user_by_pk(self, user_pk):
        if self.user_pk != user_pk:
            raise ConflictError("Social profile and user are not linked with each other")

        self._unlink_unsafe()

    def _link_unsafe(self, user_id, user_pk):
        self.user_id = user_id
        self.user_pk = user_pk
        self.linked_at = datetime.utcnow()

    def _unlink_unsafe(self):
        self.linked_at = None
        self.user_id = None
        self.user_pk = None

    def _allow_get_scope_id(self):
        ss = SystemSettings.all_as_dict()
        return_scoped_id = ss.get('return_scoped_id', 'never')
        logger.debug('System variables', return_scoped_id=return_scoped_id)

        if return_scoped_id == 'always':
            return True
        elif return_scoped_id == 'never':
            return False
        levels = (db.session.query(Admins.level).join(
            Apps, and_(Admins._id == Apps.owner_id, Apps._id == self.app_id))).first()
        level = levels[0]
        return (level == Admins.LEVEL_PREMIUM
                or (level == Admins.LEVEL_AMAZON_PLUS and self.provider == 'amazon')
                or (level == Admins.LEVEL_LINE_PLUS and self.provider == 'line'))

    @classmethod
    def delete_by_alias(cls, app_id, alias):
        profiles = cls.query.filter_by(alias=alias).all()
        if profiles:
            user_pk = profiles[0].user_pk
            if user_pk:
                Users.delete_user(pk=user_pk, app_id=app_id)
            for p in profiles:
                p._deleted = 1
                p.pk = '%d.%d' % (int(time.time()), p._id)
                p.user_pk = None
                p.user_id = None
                p.alias = 0
        else:
            raise NotFoundError(msg='Social ID not found')

    @classmethod
    def delete_by_user_pk(cls, app_id, user_pk):
        res = Users.delete_user(pk=user_pk, app_id=app_id)
        if res > 0:
            cls.query.filter_by(user_pk=user_pk, app_id=app_id).update({
                '_deleted': 1,
                'pk': func.concat(int(time.time()), '.', cls._id),
                'user_pk': None,
                'user_id': None,
                'alias': 0
            }, synchronize_session=False)
        else:
            raise NotFoundError(msg='User ID not found')

    @classmethod
    def unlink_by_provider(cls, app_id, user_pk, providers):
        profiles = cls.query.filter_by(user_pk=user_pk, app_id=app_id).all()
        for p in profiles:
            if p.provider not in providers:
                continue
            p._unlink_unsafe()
        return len(profiles)

    @classmethod
    def add_or_update(cls, app_id, scope_id, provider, attrs):
        hashpk = hashlib.sha1('{}.{}.{}'.format(app_id, provider, scope_id).encode('utf8')).hexdigest()
        profile = cls.query.filter_by(pk=hashpk).one_or_none()
        exists = False
        if not profile:
            profile = SocialProfiles(app_id=app_id, pk=hashpk, scope_id=scope_id,
                                     provider=provider, attrs=attrs)
            db.session.add(profile)
            db.session.flush()
        else:
            if profile.verified:
                profile.login_count += 1
                exists = True
            profile.last_authorized_at = datetime.utcnow()
            profile.attrs = json.dumps(attrs)
            profile.scope_id = scope_id
        return profile, exists

    @classmethod
    def activate(cls, profile_id):
        return cls.query.filter_by(_id=profile_id).update({
            'verified': 1,
            'login_count': 1
        }, synchronize_session=False)


class Users(Base):
    __tablename__ = 'users'

    HIDDEN_FIELDS = {'pk', 'app_id'}

    pk = db.Column(db.String(128), nullable=False)
    _deleted = db.Column("deleted", db.SmallInteger, default=0)
    app_id = db.Column(db.Integer, db.ForeignKey("apps.id"), nullable=False)

    def __init__(self, app_id, pk):
        self.app_id = app_id
        self.pk = pk

    def as_dict(self):
        d = super().as_dict()
        d['user_id'] = self.pk
        return d

    @classmethod
    def delete_user(cls, app_id, pk):
        salt = gen_random_token(nbytes=4, format='hex') + '.' + str(int(time.time()))
        return cls.query.filter_by(pk=pk, app_id=app_id).update({
            '_deleted': 1,
            'pk': func.concat(salt, '.', cls._id)
        }, synchronize_session=False)

    @classmethod
    def get_full_as_dict(cls, app_id, pk):
        user = cls.query.filter_by(pk=pk, app_id=app_id).one_or_none()
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
            raise NotFoundError('User not found')


class Tokens(Base):
    __tablename__ = 'tokens'

    OA_VERSION_2 = 2
    OA_VERSION_1A = 1

    provider = db.Column(db.String(15), nullable=False)
    oa_version = db.Column(db.SmallInteger, nullable=False)
    token_type = db.Column(db.String(15), nullable=False)
    access_token = db.Column(db.String(2047))
    refresh_token = db.Column(db.String(2047))
    jwt_token = db.Column(db.String(2047))
    expires_at = db.Column(db.DateTime)
    oa1_token = db.Column(db.String(1023))
    oa1_secret = db.Column(db.String(1023))

    social_id = db.Column(db.Integer, db.ForeignKey('social_profiles.id'), nullable=False)

    def __init__(self, provider, social_id, **kwargs):
        self.provider = provider
        self.social_id = social_id
        self.token_type = kwargs.get('token_type', 'Bearer')
        self.oa_version = kwargs.get('oa_version') or self.OA_VERSION_2
        self.expires_at = kwargs.get('expires_at')
        self.access_token = kwargs.get('access_token')
        self.refresh_token = kwargs.get('refresh_token')
        self.jwt_token = kwargs.get('jwt_token')
        self.oa1_token = kwargs.get('oa1_token')
        self.oa1_secret = kwargs.get('oa1_secret')

    @classmethod
    def find_latest_by_social_id(cls, social_id):
        return cls.query.filter_by(social_id=social_id).order_by(cls._id.desc()).first()


class AuthLogs(Base):
    __tablename__ = 'auth_logs'

    STATUS_UNKNOWN = 'unknown'
    STATUS_AUTHORIZED = 'authorized'
    STATUS_WAIT_REGISTER = 'wait_reg'
    STATUS_SUCCEEDED = 'succeeded'
    STATUS_FAILED = 'failed'

    INTENT_AUTHENTICATE = 'auth'
    INTENT_ASSOCIATE = 'associate'
    INTENT_LOGIN = 'login'
    INTENT_REGISTER = 'register'
    INTENT_PAY_WITH_AMAZON = 'lpwa'

    ACTION_LOGIN = 1
    ACTION_REGISTER = 0

    provider = db.Column(db.String(15), nullable=False)
    callback_uri = db.Column(db.String(2047), nullable=False)
    callback_if_failed = db.Column("callback_failed", db.String(2047))
    nonce = db.Column(db.String(32), nullable=False)
    status = db.Column(db.String(15), nullable=False)
    is_login = db.Column(db.SmallInteger, nullable=False)
    intent = db.Column(db.String(32))
    ua = db.Column(db.String(1023))
    ip = db.Column(db.String(15))
    oa1_token = db.Column(db.String(1023))
    oa1_secret = db.Column(db.String(1023))

    app_id = db.Column(db.Integer, db.ForeignKey("apps.id"), nullable=False)
    social_id = db.Column(db.Integer, db.ForeignKey('social_profiles.id'))

    def __init__(self, provider, app_id, callback_uri, **kwargs):
        self.provider = provider
        self.app_id = app_id
        self.callback_uri = callback_uri
        self.callback_if_failed = kwargs.get('callback_if_failed')

        self.status = kwargs.get('status') or self.STATUS_UNKNOWN
        self.nonce = kwargs.get('nonce')
        self.intent = kwargs.get('intent') or self.INTENT_AUTHENTICATE
        self.oa1_token = kwargs.get('oa1_token')
        self.oa1_secret = kwargs.get('oa1_secret')

    def get_failed_callback(self):
        return self.callback_if_failed or self.callback_uri

    def set_authorized(self, social_id, is_login, nonce):
        self.nonce = nonce
        self.social_id = social_id
        self.is_login = is_login
        self.status = self.STATUS_AUTHORIZED

    def generate_oauth_state(self, **kwargs):
        return jwts.generate(sub=self._id, exp_in_seconds=3600,
                             _nonce=self.nonce, **kwargs)

    def generate_auth_token(self):
        return ests.generate(sub=self._id, exp_in_seconds=3600,
                             _nonce=self.nonce)

    @classmethod
    def parse_oauth_state(cls, oauth_state):
        log_id, args = jwts.decode(token=oauth_state)
        log = cls.query.filter_by(_id=log_id).one_or_none()

        if not log or log.nonce != args.get('_nonce'):
            raise BadRequestError('Invalid OAuth state')
        if log.status != cls.STATUS_UNKNOWN:
            raise BadRequestError('Invalid OAuth state')
        return log, args

    @classmethod
    def parse_auth_token(cls, auth_token):
        log_id, args = ests.decode(token=auth_token)
        log = cls.query.filter_by(_id=log_id).one_or_none()

        if not log or log.nonce != args.get('_nonce'):
            raise BadRequestError('Invalid auth token')
        if log.status not in [cls.STATUS_AUTHORIZED, cls.STATUS_WAIT_REGISTER]:
            raise BadRequestError('Invalid auth token')
        return log


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

    def __init__(self, provider, app_id, **kwargs):
        self.provider = provider
        self.app_id = app_id
        self.user_id = kwargs.get('user_id')
        self.nonce = kwargs.get('nonce')
        self.status = kwargs.get('status', self.STATUS_NEW)

    def generate_associate_token(self):
        return ests.generate(sub=self._id, exp_in_seconds=600,
                             _nonce=self.nonce)

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
    def parse_associate_token(cls, associate_token):
        log_id, args = ests.decode(token=associate_token)
        log = cls.query.filter_by(_id=log_id).one_or_none()

        if not log or log.nonce != args.get('_nonce'):
            raise BadRequestError('Invalid associate token')
        if log.status != cls.STATUS_NEW:
            raise BadRequestError('Invalid associate token')
        return log


class JournalLogs(Base):
    __tablename__ = 'journal_logs'

    path = db.Column(db.String(4095))
    ua = db.Column(db.String(1023))
    ip = db.Column(db.String(15))
    ref_id = db.Column(db.Integer, nullable=False)

    def __init__(self, ref_id, **kwargs):
        self.ref_id = ref_id
        self.ua = self._get_ua_safe(kwargs.get('ua'), max_len=1023)
        self.ip = kwargs.get('ip')
        self.path = kwargs.get('path')

    @staticmethod
    def _get_ua_safe(ua, max_len):
        return ua[:min(len(ua), max_len)] if ua else None
