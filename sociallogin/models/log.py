from sociallogin import db, logger
from sociallogin.exc import BadRequestError
from sociallogin.models import Base
from sociallogin.sec import jwt_token_service as jwts, easy_token_service as ests


class AuthLogs(Base):
    __tablename__ = 'easylogin_auth_logs'

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
    platform = db.Column(db.String(8), nullable=False)

    oa1_token = db.Column(db.String(1023))
    oa1_secret = db.Column(db.String(1023))

    app_id = db.Column(db.Integer, db.ForeignKey("apps.id"), nullable=False)
    social_id = db.Column(db.Integer, db.ForeignKey('social_profiles.id'))

    def __init__(self, provider, app_id, callback_uri, **kwargs):
        self.provider = provider
        self.app_id = app_id
        self.callback_uri = callback_uri
        self.callback_if_failed = kwargs.get('callback_if_failed')
        self.status = self.STATUS_UNKNOWN

        self.platform = kwargs.get('platform') or 'web'
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
        return jwts.generate(sub=self._id, exp_in_seconds=3600, aud=self.app_id,
                             _nonce=self.nonce, **kwargs)

    def generate_auth_token(self, **kwargs):
        return ests.generate(sub=self._id, exp_in_seconds=3600,
                             _type='auth', _nonce=self.nonce, **kwargs)

    @classmethod
    def parse_oauth_state(cls, oauth_state):
        log_id, args = jwts.decode(token=oauth_state)
        log = cls.query.filter_by(_id=log_id).one_or_none()

        if not log or log.nonce != args.get('_nonce'):
            logger.debug('Invalid OAuth state or nonce does not match')
            raise BadRequestError('Invalid OAuth state')
        if log.status != cls.STATUS_UNKNOWN:
            logger.debug('Validate OAuth state failed. Illegal auth log status.',
                         status=log.status, expected=cls.STATUS_UNKNOWN)
            raise BadRequestError('Invalid OAuth state')
        return log, args

    @classmethod
    def parse_auth_token(cls, auth_token):
        log_id, args = ests.decode(token=auth_token)
        log = cls.query.filter_by(_id=log_id).one_or_none()

        if not log or log.nonce != args.get('_nonce'):
            logger.debug('Invalid auth token or nonce does not match')
            raise BadRequestError('Invalid auth token')
        if log.status not in [cls.STATUS_AUTHORIZED, cls.STATUS_WAIT_REGISTER]:
            logger.debug('Validate auth token failed. Illegal auth log status.',
                         status=log.status,
                         expected=[cls.STATUS_AUTHORIZED, cls.STATUS_WAIT_REGISTER])
            raise BadRequestError('Invalid auth token')
        return log, args


class AssociateLogs(Base):
    __tablename__ = 'easylogin_associate_logs'

    STATUS_NEW = 'new'
    STATUS_AUTHORIZING = 'authorizing'
    STATUS_SUCCEEDED = 'succeeded'
    STATUS_FAILED = 'failed'

    provider = db.Column(db.String(15), nullable=False)
    dst_social_id = db.Column(db.BigInteger, nullable=False)
    status = db.Column(db.String(15), nullable=False)
    nonce = db.Column(db.String(32), nullable=False)

    app_id = db.Column(db.Integer, db.ForeignKey("apps.id"), nullable=False)

    def __init__(self, provider, app_id, social_id, **kwargs):
        self.provider = provider
        self.app_id = app_id
        self.dst_social_id = social_id
        self.nonce = kwargs.get('nonce')
        self.status = kwargs.get('status', self.STATUS_NEW)

    def generate_associate_token(self):
        return ests.generate(sub=self.dst_social_id, exp_in_seconds=600,
                             _type='associate', _nonce=self.nonce)

    @classmethod
    def parse_associate_token(cls, associate_token):
        social_id, args = ests.decode(token=associate_token)
        log = cls.query.filter_by(dst_social_id=social_id).order_by(cls._id.desc()).first()

        if not log or log.nonce != args.get('_nonce'):
            logger.debug('Invalid associate token or nonce does not match')
            raise BadRequestError('Invalid associate token')
        if log.status != cls.STATUS_NEW:
            logger.debug('Illegal associate log status', status=log.status, expected=cls.STATUS_NEW)
            raise BadRequestError('Invalid associate token')
        return log


class JournalLogs(Base):
    __tablename__ = 'easylogin_journal_logs'

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
