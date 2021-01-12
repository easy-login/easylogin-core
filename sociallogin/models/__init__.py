import json
from datetime import datetime

from sqlalchemy.ext.compiler import compiles
from sqlalchemy.sql import expression
from sqlalchemy.types import DateTime

from sociallogin import db
from sociallogin.utils import convert_to_user_timezone


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
        return convert_to_user_timezone(dt).isoformat() if dt else None


from .admin import Admins
from .app import Apps
from .channel import Channels
from .provider import Providers
from .user import Users
from .system_setting import SystemSettings
from .token import Tokens
from .log import AuthLogs, AssociateLogs, JournalLogs
from .social_profile import SocialProfiles
