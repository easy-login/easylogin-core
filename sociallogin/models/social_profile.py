import hashlib
import json
import time
from datetime import datetime

from sqlalchemy import func, and_, not_

from sociallogin import db, logger
from sociallogin.atomic import generate_64bit_id
from sociallogin.exc import ConflictError, NotFoundError, BadRequestError
from sociallogin.models import Base, Users, Providers, Apps, SystemSettings, Admins


class SocialProfiles(Base):
    __tablename__ = 'easylogin_social_profiles'

    HIDDEN_FIELDS = {'pk', 'scope_id', 'attrs', 'alias', 'user_id', 'app_id'}

    provider = db.Column(db.String(15), nullable=False)
    pk = db.Column(db.String(40), unique=True, nullable=False)
    attrs = db.Column(db.Unicode(8191), nullable=False)
    scope_id = db.Column(db.String(255), nullable=False)
    last_authorized_at = db.Column("authorized_at", db.DateTime)
    login_count = db.Column(db.Integer, default=0, nullable=False)
    verified = db.Column(db.SmallInteger, default=0, nullable=False)
    linked_at = db.Column(db.DateTime)
    alias = db.Column(db.BigInteger, nullable=False)

    _deleted = db.Column("deleted", db.SmallInteger, default=0)
    _prohibited = db.Column("prohibited", db.SmallInteger, default=0)

    user_id = db.Column(db.Integer, db.ForeignKey("easylogin_users.id"))
    app_id = db.Column(db.Integer, db.ForeignKey("easylogin_apps.id"), nullable=False)

    def __init__(self, *args, **kwargs):
        self.app_id = kwargs['app_id']
        self.provider = kwargs['provider']
        self.attrs = json.dumps(kwargs['attrs'])
        self.last_authorized_at = datetime.utcnow()
        self.alias = generate_64bit_id(shard=self.app_id)
        self.scope_id = kwargs['scope_id']
        self.pk = kwargs['pk']

    def as_dict(self, user_pk=None, fetch_user=False, pretty=False):
        d = super().as_dict()
        d['social_id'] = str(self.alias)
        d['verified'] = bool(self.verified)
        d['user_id'] = Users.get_user_pk(_id=self.user_id) if fetch_user else user_pk

        if self._prohibited:
            d['attrs'] = None
            d['scope_id'] = None
        else:
            if pretty:
                d['provider'] = self.provider.upper() \
                    if self.provider != 'yahoojp' else 'YAHOO JAPAN'
                d['attrs'] = self._normalize_attributes()
            else:
                d['attrs'] = json.loads(self.attrs, encoding='utf8')
            if self._allow_get_scope_id():
                d['attrs']['id'] = self.scope_id
                d['scope_id'] = self.scope_id
        return d

    def _normalize_attributes(self):
        provider = Providers.query.filter_by(name=self.provider).one_or_none()
        fields = json.loads(provider.basic_fields, encoding='utf8')
        fields.extend(json.loads(provider.advanced_fields, encoding='utf8'))
        fields = {e['key']: e['name'] for e in fields}

        d = dict()
        attrs = json.loads(self.attrs, encoding='utf8')
        for k, v in attrs.items():
            newk = fields.get(k)
            if newk:
                d[newk] = v
        return d

    def merge_with(self, user_pk=None, alias=None):
        if not user_pk and alias <= 0:
            raise BadRequestError('At least one parameter dst_user_id or '
                                  'dst_social_id must be provided')
        profiles = SocialProfiles.find_by_pk(app_id=self.app_id, user_pk=user_pk) \
            if user_pk else SocialProfiles.query.filter_by(alias=alias)
        if not profiles:
            raise NotFoundError('Destination User ID or Social ID not found')

        dst_profile = profiles[0]
        self._merge_unsafe(dst_profile)

    def _merge_unsafe(self, dst_profile):
        self.user_id = dst_profile.user_id
        self.alias = dst_profile.alias
        self.linked_at = datetime.utcnow() if self.user_id else None

    def _link_unsafe(self, user_id):
        self.user_id = user_id
        self.linked_at = datetime.utcnow()

    def _unlink_unsafe(self):
        self.linked_at = None
        self.user_id = None

    def _delete_info_unsafe(self):
        self._prohibited = 1

    def _delete_unsafe(self):
        self._deleted = 1
        self.pk = '%d.%d' % (int(time.time()), self._id)
        self.user_id = None
        self.alias = 0

    def _allow_get_scope_id(self):
        ss = SystemSettings.all_as_dict()
        return_scoped_id = ss.get('return_scoped_id', 'never')
        logger.debug('System variables', return_scoped_id=return_scoped_id)

        if return_scoped_id == 'always':
            return True
        elif return_scoped_id == 'never':
            return False
        level = (db.session.query(Admins.level).join(
            Apps, and_(Admins._id == Apps.owner_id, Apps._id == self.app_id)).scalar())
        return Admins.check_has_plus_level(provider=self.provider, level=level)

    @classmethod
    def link_with_user(cls, app_id, alias, user_pk, create_if_not_exist=True):
        profiles = cls.query.filter_by(alias=alias).all()
        if not profiles:
            raise NotFoundError('Social ID not found')
        if profiles[0].user_id:
            raise ConflictError('Unacceptable operation. '
                                'Social profile has linked with an exists user')
        num_user_same_pk = (db.session.query(func.count(SocialProfiles._id))
                            .join(Users, and_(Users._id == SocialProfiles.user_id,
                                              Users.pk == user_pk, Users.app_id == app_id))
                            .scalar())
        if num_user_same_pk > 0:
            raise ConflictError('User has linked with another social profile')

        user = Users.query.filter_by(pk=user_pk, app_id=app_id).one_or_none()
        if not user:
            if not create_if_not_exist:
                raise NotFoundError('User not found')
            user = Users(pk=user_pk, app_id=app_id)
            db.session.add(user)
            db.session.flush()
        for p in profiles:
            p._link_unsafe(user._id)

    @classmethod
    def unlink_from_user(cls, app_id, alias, user_pk):
        user_id = db.session.query(Users._id).filter_by(pk=user_pk, app_id=app_id).scalar()
        if not user_id:
            raise NotFoundError('User ID not found')
        return cls.query.filter_by(alias=alias, user_id=user_id).update({
            'linked_at': None,
            'user_id': None
        }, synchronize_session=False)

    @classmethod
    def merge_profiles(cls, app_id, src_user_pk=None, src_alias=None,
                       dst_user_pk=None, dst_alias=None):
        src_profiles = cls.find_by_pk(app_id=app_id, user_pk=src_user_pk) \
            if src_user_pk else cls.query.filter_by(alias=src_alias).all()
        if not src_profiles:
            raise NotFoundError('Source User ID or Social ID not found')

        dst_profiles = cls.find_by_pk(app_id=app_id, user_pk=dst_user_pk) \
            if dst_user_pk else cls.query.filter_by(alias=dst_alias).all()
        if not dst_profiles:
            raise NotFoundError('Destination User ID or Social ID not found')

        associated_providers = []
        for p in dst_profiles:
            associated_providers.append(p.provider)
        for p in src_profiles:
            if p.provider in associated_providers:
                raise ConflictError(
                    msg='Unacceptable operation. '
                        'Source profile has associated with a provider same in destination profile',
                    data={
                        'conflict_provider': p.provider,
                        'associated_providers': ', '.join(associated_providers)
                    })
        dst_profile = dst_profiles[0]
        for p in src_profiles:
            p._merge_unsafe(dst_profile)

    @classmethod
    def delete_profile(cls, app_id, user_pk=None, alias=None):
        profiles = []
        if user_pk:
            user = Users.query.filter_by(pk=user_pk, app_id=app_id).one_or_none()
            if user:
                Users.delete_by_id(_id=user._id)
                profiles = cls.query.filter_by(user_id=user._id).all()
        else:
            profiles = cls.query.filter_by(alias=alias).all()
            if profiles:
                user_id = profiles[0].user_id
                if user_id:
                    Users.delete_by_id(_id=user_id)
        for p in profiles:
            p._delete_unsafe()
        return len(profiles)

    @classmethod
    def find_by_pk(cls, app_id, user_pk):
        return (cls.query.join(
            Users, and_(Users._id == SocialProfiles.user_id,
                        Users.pk == user_pk, Users.app_id == app_id)
        ).all())

    @classmethod
    def reset_info(cls, app_id, user_pk=None, alias=None):
        if user_pk:
            profiles = cls.find_by_pk(app_id=app_id, user_pk=user_pk)
            for p in profiles:
                p._reset_info()
            return len(profiles)
        else:
            return cls.query.filter_by(alias=alias).update({
                '_prohibited': 1
            }, synchronize_session=False)

    @classmethod
    def disassociate_provider(cls, app_id, providers, user_pk=None, alias=None):
        if user_pk:
            profiles = cls.find_by_pk(user_pk=user_pk, app_id=app_id)
            for p in profiles:
                if p.provider not in providers:
                    continue
                p._delete_unsafe()
            return len(profiles)
        else:
            return (cls.query
                .filter(cls.alias == alias, not_(cls.provider.in_(providers)))
                .update({
                    '_deleted': 1,
                    'pk': func.concat(int(time.time()), '.', cls._id),
                    'user_id': None,
                    'alias': 0
            }, synchronize_session=False))

    @classmethod
    def add_or_update(cls, app_id, scope_id, provider, attrs):
        hashpk = hashlib.sha1('{}.{}.{}'.format(app_id, provider, scope_id).encode('utf8')).hexdigest()
        profile = cls.query.filter_by(pk=hashpk).one_or_none()
        exists = False
        if not profile:
            profile = SocialProfiles(app_id=app_id, pk=hashpk, scope_id=scope_id,
                                     provider=provider, attrs=attrs)
            db.session.add(profile)
            db.session.flush()
        else:
            if profile.verified:
                profile.login_count += 1
                exists = True
            profile.last_authorized_at = datetime.utcnow()
            profile.attrs = json.dumps(attrs)
            profile.scope_id = scope_id
            profile._prohibited = 0
        return profile, exists

    @classmethod
    def activate(cls, profile_id):
        return cls.query.filter_by(_id=profile_id).update({
            'verified': 1,
            'login_count': 1
        }, synchronize_session=False)

    @classmethod
    def get_full_profile(cls, app_id, user_pk=None, alias=None, pretty=False):
        profiles = cls.find_by_pk(app_id=app_id, user_pk=user_pk) \
            if user_pk else SocialProfiles.query.filter_by(alias=alias).all()
        if not profiles:
            raise NotFoundError('User ID or Social ID not found')

        last_profile = None
        login_count = 0
        for p in profiles:
            login_count += p.login_count
            if not last_profile:
                last_profile = p
                continue
            if last_profile.last_authorized_at < p.last_authorized_at:
                last_profile = p
        user = Users.query.filter_by(_id=last_profile.user_id).one_or_none()
        user_attrs = user.as_dict() if user else {'user_id': None}
        user_attrs.update({
            'last_logged_in_provider': last_profile.provider,
            'last_logged_in_at': cls.to_isoformat(last_profile.last_authorized_at),
            'login_count': login_count,
            'social_id': str(last_profile.alias)
        })
        return {
            'user': user_attrs,
            'profiles': [
                p.as_dict(user_pk=user.pk if user else None,
                          fetch_user=False, pretty=pretty)
                for p in profiles
            ]
        }

    @classmethod
    def social_id_to_scope_id(cls, app_id, social_ids):
        return db.session.query(SocialProfiles.scope_id)\
            .filter(cls.alias.in_(social_ids), cls.app_id == app_id).all()
