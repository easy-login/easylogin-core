from sociallogin import db


class Providers(db.Model):
    __tablename__ = 'easylogin_providers'

    _id = db.Column("id", db.Integer, primary_key=True)
    name = db.Column(db.String(15), nullable=False)
    version = db.Column(db.String(15), nullable=False)
    required_permissions = db.Column(db.String(1023), nullable=False)
    basic_fields = db.Column(db.String(4095), nullable=False)
    advanced_fields = db.Column(db.String(4095), nullable=False)
    options = db.Column(db.String(4095))
