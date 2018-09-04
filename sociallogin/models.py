import json
from datetime import datetime, timezone, timedelta
import hashlib
from flask import abort

from sociallogin import db


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


class Providers(db.Model):
    __tablename__ = 'providers'

    _id = db.Column("id", db.String(15), primary_key=True)
    version = db.Column(db.String(7), nullable=False)
    permissions = db.Column(db.String(1023), nullable=False)
    required_permissions = db.Column("permissions_required", db.String(1023), nullable=False)

    def __init__(self, _id, version, permissions, required_permissions):
        self._id = _id
        self.version = version
        self.permissions = permissions
        self.required_permissions = required_permissions

    @classmethod
    def init(cls):
        try:
            providers = [
                Providers(_id='line', version='v2.1',
                          permissions='profile,openid,email',
                          required_permissions=''),
                Providers(_id='amazon', version='v2',
                          permissions='profile,profile:user_id,postal_code',
                          required_permissions=''),
                Providers(_id='yahoojp', version='v2',
                          permissions='profile,openid,email,address',
                          required_permissions='')
            ]
            db.session.bulk_save_objects(providers)
            db.session.commit()
        except Exception as e:
            print(e)
            pass


class Admins(Base):
    __tablename__ = 'admins'

    username = db.Column(db.String(32), nullable=False)
    email = db.Column(db.String(32), nullable=False)
    password = db.Column(db.String(64), nullable=False)
    salt = db.Column(db.String(8), nullable=False)
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
    login_count = db.Column(db.Integer, default=0, nullable=False)
    linked_at = db.Column(db.DateTime)
    _deleted = db.Column("deleted", db.Boolean, default=False)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    user_pk = db.Column(db.String(255))
    app_id = db.Column(db.Integer, db.ForeignKey("apps.id"), nullable=False)

    def __init__(self, app_id, pk, provider, attrs, last_authorized_at=datetime.now()):
        self.app_id = app_id
        self.pk = pk
        self.provider = provider
        self.attrs = json.dumps(attrs)
        self.last_authorized_at = last_authorized_at

    def as_dict(self):
        d = super().as_dict()
        d['attrs'] = json.loads(d['attrs'], encoding='utf8')
        d['social_id'] = self._id
        d['user_id'] = d['user_pk']
        del d['user_pk']
        return d

    def link_to_end_user(self, user_pk, create_user=True):
        user = Users.query.filter_by(app_id=self.app_id, pk=user_pk).one_or_none()
        if not user:
            if not create_user:
                abort(404, 'User ID not found')
            user = Users(pk=user_pk, app_id=self.app_id)
            db.session.add(user)
            db.session.flush()

        self.user_id = user._id
        self.user_pk = user_pk
        self.linked_at = datetime.now()

    def unlink_from_end_user(self, user_pk):
        if self.user_pk != user_pk:
            abort(409, "Social profile and user don't linked with each other")
        self._unlink_unsafe()

    def _unlink_unsafe(self):
        self.linked_at = None
        self.user_id = None
        self.user_pk = None

    @classmethod
    def unlink_by_provider(cls, app_id, user_pk, providers):
        profiles = cls.query.filter_by(app_id=app_id, user_pk=user_pk).all()
        for p in profiles:
            if p.provider not in providers:
                continue
            p._unlink_unsafe()
            db.session.merge(p)

    @classmethod
    def add_or_update(cls, app_id, pk, provider, attrs):
        hashpk = hashlib.sha1((provider + '.' + pk).encode('utf8')).hexdigest()
        profile = cls.query.filter_by(app_id=app_id, pk=hashpk).one_or_none()
        if not profile:
            profile = SocialProfiles(app_id=app_id, pk=hashpk, provider=provider, attrs=attrs)
            db.session.add(profile)
            db.session.flush()
        else:
            profile.last_authorized_at = datetime.now()
            profile.login_count += 1
        return profile


class Users(Base):
    __tablename__ = 'users'

    pk = db.Column(db.String(255), unique=True, nullable=False)
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

    provider = db.Column(db.String(15), nullable=False)
    callback_uri = db.Column(db.String(2047), nullable=False)
    callback_if_failed = db.Column("callback_failed", db.String(2047))
    oauth_state = db.Column(db.String(32), nullable=False)
    status = db.Column(db.String(15), nullable=False)
    auth_token = db.Column(db.String(32))
    token_expires = db.Column(db.DateTime)
    ua = db.Column(db.String(4095))
    ip = db.Column(db.String(15))

    app_id = db.Column(db.Integer, db.ForeignKey("apps.id"), nullable=False)
    social_id = db.Column(db.Integer, db.ForeignKey('social_profiles.id'))

    def __init__(self, provider, app_id, oauth_state, callback_uri,
                 callback_if_failed=None, ua=None, ip=None, status=STATUS_UNKNOWN):
        self.provider = provider
        self.app_id = app_id
        self.oauth_state = oauth_state
        self.callback_uri = callback_uri
        self.callback_if_failed = callback_if_failed
        self.ua = ua
        self.ip = ip
        self.status = status

    def safe_get_failed_callback(self):
        return self.callback_if_failed or self.callback_uri

    def set_authorized(self, social_id, auth_token):
        self.auth_token = auth_token
        self.token_expires = datetime.now() + timedelta(seconds=600)
        self.social_id = social_id
        self.status = self.STATUS_AUTHORIZED

    @classmethod
    def find_by_one_time_token(cls, auth_token):
        return cls.query.filter_by(auth_token=auth_token).order_by(cls._id.desc()).first()


class AssociateLogs(Base):
    __tablename__ = 'associate_logs'

    STATUS_UNKNOWN = 'initialized'
    STATUS_AUTHORIZED = 'authorized'
    STATUS_SUCCEEDED = 'succeeded'
    STATUS_FAILED = 'failed'

    provider = db.Column(db.String(15), nullable=False)
    status = db.Column(db.String(15), nullable=False)
    nonce = db.Column(db.String(32), nullable=False)

    app_id = db.Column(db.Integer, db.ForeignKey("apps.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __init__(self, provider, app_id, user_id, nonce, status=STATUS_UNKNOWN):
        self.provider = provider
        self.app_id = app_id
        self.user_id = user_id
        self.nonce = nonce
        self.status = status
