from sociallogin import db
from sociallogin.models import Base


class Apps(Base):
    __tablename__ = 'easylogin_apps'

    name = db.Column(db.String(127), nullable=False)
    api_key = db.Column(db.String(64), nullable=False)
    allowed_ips = db.Column(db.String(255))
    callback_uris = db.Column(db.Text, nullable=False)
    options = db.Column(db.String(1023))

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
