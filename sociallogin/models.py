# from sociallogin import db
from sociallogin import db
from datetime import datetime


# Define a base model for other database tables to inherit
class Base(db.Model):
    __abstract__  = True

    _id           = db.Column(db.Integer, primary_key=True)
    created_at    = db.Column(db.DateTime, default=db.func.current_timestamp())
    modified_at   = db.Column(db.DateTime, default=db.func.current_timestamp(),
                                        onupdate=db.func.current_timestamp())
    
    def __repr__(self):
        return str(self.__dict__)


class Providers(db.Model):
    __tablename__ = 'providers'

    _id = db.Column(db.String(8), primary_key=True, nullable=False)
    version = db.Column(db.String(8))
    permissions = db.Column(db.String(1024), nullable=False)


class SiteOwners(Base):
    __tablename__ = 'site_owners'

    username = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(32), nullable=False)
    password = db.Column(db.String(64), nullable=False)
    salt = db.Column(db.String(8), nullable=False)
    fullname = db.Column(db.String(64))
    address = db.Column(db.String(128))
    phone = db.Column(db.String(12))
    company = db.Column(db.String(64))


class Sites(Base):
    __tablename__ = 'sites'

    domain = db.Column(db.String(64), nullable=False)
    api_key = db.Column(db.String(128), nullable=False)
    callback_uri = db.Column(db.String(1024), nullable=False)
    whilelist = db.Column(db.String(512))
    description = db.Column(db.String(512))

    owner_id = db.Column(db.Integer, db.ForeignKey("site_owners._id"), nullable=False)


class SiteProviders(Base):
    __tablename__ = 'site_providers'

    provider = db.Column(db.String(8), nullable=False)
    client_id = db.Column(db.String(128), nullable=False)
    client_secret = db.Column(db.String(256), nullable=False)
    permissions = db.Column(db.String(1024), default='', nullable=False)

    site_id = db.Column(db.Integer, db.ForeignKey("sites._id"), nullable=False)


class Users(Base):
    __tablename__ = 'users'

    provider = db.Column(db.String(8), nullable=False)
    identifier = db.Column(db.String(64), nullable=False)
    associate_token = db.Column(db.String(40))
    token_expires = db.Column(db.DateTime)
    last_login = db.Column(db.DateTime)
    deleted = db.Column(db.SmallInteger, default=0, nullable=False)

    site_id = db.Column(db.Integer, db.ForeignKey("sites._id"), nullable=False)

    def __init__(self, provider, identifier, site_id, last_login=datetime.now()):
        self.provider = provider
        self.identifier = identifier
        self.site_id = site_id
        self.last_login = last_login

    @classmethod
    def add_or_update(cls, provider, identifier, site_id):
        user = Users.query.filter_by(identifier=identifier).one_or_none()
        if not user:
            user = Users(provider=provider, identifier=identifier, site_id=site_id)
            db.session.add(user)
            db.session.flush()
        else:
            user.last_login = datetime.now()
            db.session.merge(user)
        return user


class UserAttributes(db.Model):
    __tablename__ = 'user_attributes'

    _id = db.Column(db.Integer, primary_key=True)
    log_id = db.Column(db.Integer, primary_key=True)
    attr = db.Column(db.String(16), primary_key=True)
    val = db.Column(db.String(256), nullable=False)

    def __init__(self, _id, log_id, attr, val):
        self._id = _id
        self.log_id = log_id
        self.attr = attr
        self.val = val

    @classmethod
    def add_many(cls, _id, log_id, attrs):
        db.session.bulk_save_objects(
            [UserAttributes(_id=_id, log_id=log_id, attr=key, val=value) 
            for key, value in attrs])


class SiteUsers(Base):
    __tablename__ = 'site_users'

    site_id = db.Column(db.Integer, db.ForeignKey("sites._id"), nullable=False)
    social_uid = db.Column(db.Integer, db.ForeignKey('users._id'), nullable=False)

    def __init__(self, _id, site_id, social_uid):
        self._id = _id
        self.site_id = site_id
        self.social_uid = social_uid


class Tokens(Base):
    __tablename__ = 'tokens'

    provider = db.Column(db.String(8), nullable=False)
    access_token = db.Column(db.String(2048), nullable=False)
    refresh_token = db.Column(db.String(2048))
    jwt_token = db.Column(db.String(2048))
    expires_at = db.Column(db.DateTime, nullable=False)
    scope = db.Column(db.String(1024))
    token_type = db.Column(db.String(16))

    user_id = db.Column(db.Integer, db.ForeignKey('users._id'), nullable=False)

    def __init__(self, provider, access_token, expires_at, refresh_token=None, 
                jwt_token=None, scope=None, token_type='Bearer', user_id=None):
        self.provider = provider
        self.access_token = access_token
        self.expires_at = expires_at
        self.refresh_token = refresh_token
        self.jwt_token = jwt_token
        self.scope = scope
        self.token_type = token_type
        self.user_id = user_id


class Logs(Base):
    __tablename__ = 'logs'

    provider = db.Column(db.String(8), nullable=False)
    nonce = db.Column(db.String(40), nullable=False)
    callback_uri = db.Column(db.String(1024), nullable=False)
    ua = db.Column(db.String(512))
    ip = db.Column(db.String(16))
    status = db.Column(db.String(8), nullable=False)

    site_id = db.Column(db.Integer, db.ForeignKey("sites._id"), nullable=False)

    def __init__(self, provider, site_id, nonce, callback_uri, ua=None, ip=None, status='unknown'):
        self.provider = provider
        self.site_id = site_id
        self.nonce = nonce
        self.callback_uri = callback_uri
        self.ua = ua
        self.ip = ip
        self.status = status
