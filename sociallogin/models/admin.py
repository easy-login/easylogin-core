from sociallogin import db


class Admins(db.Model):
    __tablename__ = 'easylogin_admins'

    LEVEL_NORMAL = 0
    LEVEL_PREMIUM = 65535
    LEVEL_LINE_PLUS = 1
    LEVEL_AMAZON_PLUS = 2
    LEVEL_YAHOOJP_PLUS = 4
    LEVEL_FACEBOOK_PLUS = 8
    LEVEL_TWITTER_PLUS = 16
    LEVEL_GOOGLE_PLUS = 32
    LEVEL_AMAZON_AND_LINE_PLUS = LEVEL_LINE_PLUS | LEVEL_AMAZON_PLUS

    MAP_LEVEL_PROVIDERS = {
        'line': LEVEL_LINE_PLUS,
        'amazon': LEVEL_AMAZON_PLUS,
        'yahoojp': LEVEL_YAHOOJP_PLUS,
        'facebook': LEVEL_FACEBOOK_PLUS,
        'twitter': LEVEL_TWITTER_PLUS,
        'google': LEVEL_GOOGLE_PLUS
    }

    HIDDEN_FIELDS = {'password', 'is_superuser'}

    _id = db.Column("id", db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(64), nullable=False)
    password = db.Column(db.String(128), nullable=False)
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    is_superuser = db.Column(db.SmallInteger, default=0)
    is_active = db.Column(db.SmallInteger, default=1)
    level = db.Column(db.Integer, default=0)
    delete = db.Column(db.SmallInteger, default=0)

    def as_dict(self):
        return {
            'username': self.username,
            'email': self.email,
            'is_superuser': bool(self.is_superuser),
            'level': self.level,
            'first_name': self.first_name,
            'last_name': self.last_name
        }

    @classmethod
    def check_has_plus_level(cls, provider, level):
        return cls.MAP_LEVEL_PROVIDERS[provider] & level > 0
