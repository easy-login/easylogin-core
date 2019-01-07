import hashlib
import json
import time
from datetime import datetime, timedelta

from sqlalchemy import func, and_, not_
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.sql import expression
from sqlalchemy.types import DateTime

from shopifyapp import db, logger
from shopifyapp.utils import convert_to_user_timezone


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


class Stores(Base):
    __tablename__ = 'stores'

    store_url = db.Column(db.String(255), unique=True, nullable=False)
    easylogin_app_id = db.Column(db.String(255))
    installed_at = db.Column(db.DateTime)
    installed = db.Column(db.SmallInteger, default=0, nullable=False)
    last_activated_at = db.Column('activated_at', db.DateTime)

    def __init__(self, **kwargs):
        self.store_url = kwargs.get('store_url')
        self.last_activated_at = utcnow()

    @classmethod
    def set_installed(cls, store_url, app_id):
        return cls.query.filter_by(store_url=store_url).update({
            'easylogin_app_id': app_id,
            'installed_at': utcnow(),
            'installed': 1
        }, synchronize_session=False)


class Customer(Base):
    __tablename__ = 'customers'

    shopify_id = db.Column(db.BigInteger, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)


class AccessTokens(Base):
    __tablename__ = 'tokens'

    online_access = db.Column(db.SmallInteger, default=0, nullable=False)
    access_token = db.Column(db.String(2047), nullable=False)
    refresh_token = db.Column(db.String(2047))
    expires_at = db.Column(db.DateTime)
    store_id = db.Column(db.Integer, db.ForeignKey('stores.id'), nullable=False)

    def __init__(self, **kwargs):
        self.access_token = kwargs.get('access_token')
        self.refresh_token = kwargs.get('refresh_token')
        self.expires_at = kwargs.get('expires_at')
        self.store_id = kwargs.get('store_id')

    @classmethod
    def find_latest_by_store_id(cls, store_id):
        return cls.query.filter_by(store_id=store_id).order_by(cls._id.desc()).first()
