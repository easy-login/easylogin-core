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


class Providers(db.Model):
    __tablename__ = 'easylogin_providers'

    _id = db.Column("id", db.Integer, primary_key=True)
    name = db.Column(db.String(15), nullable=False)
    version = db.Column(db.String(15), nullable=False)
    required_permissions = db.Column(db.String(1023), nullable=False)
    basic_fields = db.Column(db.String(4095), nullable=False)
    advanced_fields = db.Column(db.String(4095), nullable=False)
    options = db.Column(db.String(4095))
