from datetime import datetime, timedelta

from sociallogin import db, logger, app
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
