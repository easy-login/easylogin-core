import hashlib
import json
import time
from datetime import datetime, timedelta

from sqlalchemy import func, and_, not_
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.sql import expression
from sqlalchemy.types import DateTime

from sociallogin import db, logger, app
from sociallogin.atomic import generate_64bit_id
from sociallogin.exc import ConflictError, NotFoundError, BadRequestError
from sociallogin.sec import jwt_token_service as jwts, easy_token_service as ests
from sociallogin.utils import gen_random_token, convert_to_user_timezone
from sociallogin.models import Base


class SystemSettings(Base):
    __tablename__ = 'easylogin_system_settings'

    _last_update_ = datetime.now()
    _cache_ = dict()

    name = db.Column(db.String(64), nullable=False)
    value = db.Column(db.String(64), nullable=False)

    @classmethod
    def all_as_dict(cls):
        # keep cache in 10 minutes, only in production mode
        if app.config['DEBUG']:
            rows = cls.query.all()
            return {e.name: e.value for e in rows}
        else:
            now = datetime.now()
            if not cls._cache_ or cls._last_update_ + timedelta(minutes=10) < now:
                logger.info('Refresh System settings cache',
                            current_size=len(cls._cache_), last_update=cls._last_update_)
                rows = cls.query.all()
                cls._cache_ = {e.name: e.value for e in rows}
                cls._last_update_ = now
            return cls._cache_
