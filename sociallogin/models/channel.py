from sociallogin import db
from sociallogin.models import Base


class Channels(Base):
    __tablename__ = 'easylogin_channels'

    provider = db.Column(db.String(15), nullable=False)
    api_version = db.Column(db.String(15), nullable=False)
    client_id = db.Column(db.String(255), nullable=False)
    client_secret = db.Column(db.String(255), nullable=False)
    permissions = db.Column(db.String(1023), nullable=False)
    required_fields = db.Column(db.String(1023), nullable=False)
    options = db.Column(db.String(1023))

    app_id = db.Column(db.Integer, db.ForeignKey("easylogin_apps.id"), nullable=False)

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
