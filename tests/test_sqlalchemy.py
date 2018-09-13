from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy

# Define the WSGI application object
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@localhost/sociallogin?charset=utf8mb4'
# SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://guest:123456@192.168.9.89/nhatanhdb?charset=utf8mb4'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SQLALCHEMY_NATIVE_UNICODE = True'] = True

# Define the database object which is imported
# by modules and controllers
db = SQLAlchemy(app)


class Providers(db.Model):
    global db
    __tablename__ = 'providers'

    _id = db.Column("id", db.String(15), primary_key=True)
    version = db.Column(db.String(7), nullable=False)
    permissions = db.Column(db.String(1023), nullable=False)
    required_permissions = db.Column("permissions_required", db.String(1023), nullable=False)

    def __init__(self, _id, version, permissions, required_permissions):
        self._id = _id
        self.version = version
        self.permissions = permissions
        self.required_permissions = required_permissions


@app.route('/tests/<provider>/<version>')
def update_provider(provider, version):
    try:
        # p = Providers.query.filter_by(_id=provider).one_or_none()
        # p.version = version
        Providers.query.filter_by(_id=provider).update({'version': version})

        msg = request.args['msg']
        db.session.commit()
        return jsonify({'msg': msg})
    except Exception as e:
        db.session.rollback()
        return jsonify({'err': repr(e)})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
