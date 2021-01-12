from sociallogin import db
from sociallogin.models import Base


class Tokens(Base):
    __tablename__ = 'easylogin_tokens'

    OA_VERSION_2 = 2
    OA_VERSION_1A = 1

    provider = db.Column(db.String(15), nullable=False)
    oa_version = db.Column(db.SmallInteger, nullable=False)
    token_type = db.Column(db.String(15), nullable=False)
    access_token = db.Column(db.String(2047))
    refresh_token = db.Column(db.String(2047))
    id_token = db.Column(db.String(2047))
    expires_at = db.Column(db.DateTime)
    oa1_token = db.Column(db.String(1023))
    oa1_secret = db.Column(db.String(1023))

    social_id = db.Column(db.Integer, db.ForeignKey('easylogin_social_profiles.id'), nullable=False)

    def __init__(self, provider, social_id, **kwargs):
        self.provider = provider
        self.social_id = social_id
        self.token_type = kwargs.get('token_type', 'Bearer')
        self.oa_version = kwargs.get('oa_version') or self.OA_VERSION_2
        self.expires_at = kwargs.get('expires_at')
        self.access_token = kwargs.get('access_token')
        self.refresh_token = kwargs.get('refresh_token')
        self.id_token = kwargs.get('id_token')
        self.oa1_token = kwargs.get('oa1_token')
        self.oa1_secret = kwargs.get('oa1_secret')

    @classmethod
    def find_latest_by_social_id(cls, social_id):
        return cls.query.filter_by(social_id=social_id).order_by(cls._id.desc()).first()
