import json
from datetime import datetime, timezone

from sociallogin import db


# Define a base model for other database tables to inherit
class Base(db.Model):
    __abstract__  = True

    _id           = db.Column("_id", db.Integer, primary_key=True)
    created_at    = db.Column(db.DateTime, default=db.func.current_timestamp())
    modified_at   = db.Column(db.DateTime, default=db.func.current_timestamp(),
                                        onupdate=db.func.current_timestamp())
    
    def __repr__(self):
        return str(self.as_dict())

    def as_dict(self):
        attrs = {}
        for k, v in self.__dict__.items():
            if k == '_sa_instance_state' or k == '_deleted': 
                continue
            if isinstance(v, datetime):
                v = v.replace(tzinfo=timezone.utc).isoformat()
            attrs[k] = v
        return attrs


class Providers(Base):
    __tablename__ = 'providers'

    name = db.Column(db.String(15), nullable=False)
    version = db.Column(db.String(7))
    permissions = db.Column(db.String(1023), nullable=False)


class Admins(Base):
    __tablename__ = 'admins'

    username = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(32), nullable=False)
    password = db.Column(db.String(64), nullable=False)
    salt = db.Column(db.String(8), nullable=False)
    fullname = db.Column(db.String(64))
    address = db.Column(db.String(128))
    phone = db.Column(db.String(12))
    company = db.Column(db.String(64))


class Apps(Base):
    __tablename__ = 'apps'

    name = db.Column(db.String(255), nullable=False)
    api_key = db.Column(db.String(255), nullable=False)
    allowed_ips = db.Column(db.String(255))
    description = db.Column(db.String(255))
    callback_uri = db.Column(db.String(65535), nullable=False)

    owner_id = db.Column(db.Integer, db.ForeignKey("admins._id"), nullable=False)

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

    app_id = db.Column(db.Integer, db.ForeignKey("apps._id"), nullable=False)


class SocialProfiles(Base):
    __tablename__ = 'social_profiles'

    provider = db.Column(db.String(15), nullable=False)
    identifier = db.Column(db.String(40), nullable=False)
    last_authorized_at = db.Column("authorized_at", db.DateTime)
    linked_at = db.Column(db.DateTime)
    attrs = attrs = db.Column(db.String(4095), nullable=False)
    _deleted = db.Column("deleted", db.SmallInteger, default=0, nullable=False)

    user_id = db.Column(db.String(255), db.ForeignKey("users._id"))

    def __init__(self, provider, identifier, kvattrs, last_authorized_at=datetime.now()):
        self.provider = provider
        self.identifier = identifier
        self.attrs = json.dumps(kvattrs)
        self.last_authorized_at = last_authorized_at

    def as_dict(self):
        d = super().as_dict()
        d['attrs'] = json.loads(d['attrs'], encoding='utf8')
        return d

    @classmethod
    def add_or_update(cls, provider, identifier, kvattrs):
        profile = cls.query.filter_by(identifier=identifier).one_or_none()
        if not profile:
            profile = SocialProfiles(provider=provider, identifier=identifier, kvattrs=kvattrs)
            db.session.add(profile)
            db.session.flush()
        else:
            profile.last_authorized_at = datetime.now()
            db.session.merge(profile)
        return profile

    @classmethod
    def link_to_user(cls, social_id, user_id):
        profile = SocialProfile.query.filter_by(_id=social_id).first_or_404()
        if not profile.user_id:
            profile.user_id = user_id
            profile.linked_at = datetime.now()
            db.session.commit()
        else:
            raise


class Users(db.Model):
    __tablename__ = 'users'

    _id = db.Column("_id", db.String(255), primary_key=True)
    last_logged_in_at = db.Column("last_login", db.DateTime)
    last_logged_in_provider = db.Column("last_provider", db.String(15))
    login_count = db.Column(db.Integer, nullable=False, default=0)
    _deleted = db.Column("deleted", db.Boolean, nullable=False, default=False)

    app_id = db.Column(db.Integer, db.ForeignKey("apps._id"), nullable=False)

    def __init__(_id, app_id, last_provider, login_count=0, last_login=datetime.now()):
        self._id = _id
        self.app_id = app_id
        self.last_logged_in_provider = last_provider
        self.login_count = login_count
        self.last_logged_in_at = last_login


class Tokens(Base):
    __tablename__ = 'tokens'

    provider = db.Column(db.String(15), nullable=False)
    access_token = db.Column(db.String(2047), nullable=False)
    refresh_token = db.Column(db.String(2047))
    jwt_token = db.Column(db.String(2047))
    expires_at = db.Column(db.DateTime, nullable=False)
    scope = db.Column(db.String(1023))
    token_type = db.Column(db.String(15))

    social_id = db.Column(db.Integer, db.ForeignKey('social_profiles._id'), nullable=False)

    def __init__(self, provider, access_token, expires_at, social_id,
                refresh_token=None, jwt_token=None, scope=None, token_type='Bearer'):
        self.provider = provider
        self.access_token = access_token
        self.expires_at = expires_at
        self.refresh_token = refresh_token
        self.jwt_token = jwt_token
        self.scope = scope
        self.token_type = token_type
        self.social_id = social_id


class AuthLogs(Base):
    __tablename__ = 'auth_logs'

    STATUS_UNKNOWN = 'unknown'
    STATUS_AUTHORIZED = 'authorized'
    STATUS_SUCCEEDED = 'succeeded'
    STATUS_FAILED = 'failed'

    provider = db.Column(db.String(15), nullable=False)
    nonce = db.Column(db.String(32), nullable=False)
    callback_uri = db.Column(db.String(2047), nullable=False)
    callback_if_failed = db.Column("callback_failed", db.String(2047))
    ua = db.Column(db.String(511))
    ip = db.Column(db.String(15))
    status = db.Column(db.String(15), nullable=False)
    once_token = db.Column(db.String(32))
    token_expires = db.Column(db.DateTime)

    app_id = db.Column(db.Integer, db.ForeignKey("apps._id"), nullable=False)
    social_id = db.Column(db.Integer, db.ForeignKey('social_profiles._id'))

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

    @classmethod
    def find_by_once_token(cls, once_token):
        return cls.query.filter_by(once_token=once_token).order_by(cls._id.desc()).first_or_404()
