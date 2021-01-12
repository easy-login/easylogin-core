import time

from sqlalchemy import func

from sociallogin import db
from sociallogin.models import Base
from sociallogin.utils import gen_random_token


class Users(Base):
    __tablename__ = 'easylogin_users'

    HIDDEN_FIELDS = {'pk', 'app_id'}

    pk = db.Column('ref_id', db.String(128), nullable=False)
    _deleted = db.Column("deleted", db.SmallInteger, default=0)
    app_id = db.Column(db.Integer, db.ForeignKey("easylogin_apps.id"), nullable=False)

    def __init__(self, app_id, pk):
        self.app_id = app_id
        self.pk = pk

    def as_dict(self):
        d = super().as_dict()
        d['user_id'] = self.pk
        return d

    @classmethod
    def delete_by_id(cls, _id):
        salt = gen_random_token(nbytes=4, format='hex') + '.' + str(int(time.time()))
        return cls.query.filter_by(_id=_id).update({
            '_deleted': 1,
            'pk': func.concat(salt, '.', cls._id)
        }, synchronize_session=False)

    @classmethod
    def get_user_pk(cls, _id):
        return db.session.query(cls.pk).filter_by(_id=_id).scalar()
