from datetime import datetime
import enum
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from sqlalchemy import Enum
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://edm:edm@localhost:3306/edm"
db = SQLAlchemy(app)
mail = Mail(app)


# database =================================================================
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    account = db.Column(db.String(128), unique=True, nullable=False, comment="mail")
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)
    deleted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    update_at = db.Column(db.DateTime, onupdate=datetime.now, default=datetime.now)

    # foreign key
    newsletter = db.relationship('Newsletter', backref='users')
    code = db.relationship('Registration_code', backref='users')

    # def __init__(self, name, account, password, role):
    #     self.name = name
    #     self.account = account
    #     self.password = password
    #     self.role = role

    @property
    def serialize(self):
        """Return object data in easily serializable format"""
        return {
            'id': self.id,
            'name': self.name,
            'account': self.account,
            'role': self.role,
            'deleted': self.deleted,
            'created_at': self.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            'update_at': self.update_at.strftime("%Y-%m-%d %H:%M:%S")
        }

class Role(db.Model):
    __tablename__ = "roles"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=True)
    group = db.Column(db.String(64), nullable=True)
    create_mails = db.Column(db.Boolean, default=False)
    update_mails = db.Column(db.Boolean, default=False)
    delete_mails = db.Column(db.Boolean, default=False)
    create_users = db.Column(db.Boolean, default=False)
    update_users = db.Column(db.Boolean, default=False)
    delete_users = db.Column(db.Boolean, default=False)
    create_roles = db.Column(db.Boolean, default=False)
    update_roles = db.Column(db.Boolean, default=False)
    delete_roles = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    update_at = db.Column(db.DateTime, onupdate=datetime.now, default=datetime.now)

    # foreign key
    user = db.relationship('User', backref='roles')

    # def __init__(
    #     self,
    #     name='',
    #     group='',
    #     create_mails=False,
    #     update_mails=False,
    #     delete_mails=False,
    #     create_users=False,
    #     delete_users=False,
    #     create_roles=False,
    #     update_roles=False,
    #     delete_roles=False,
    # ):
    #     self.name = name
    #     self.group = group
    #     self.create_mails = create_mails
    #     self.update_mails = update_mails
    #     self.delete_mails = delete_mails
    #     self.create_users = create_users
    #     self.delete_users = delete_users
    #     self.create_roles = create_roles
    #     self.update_roles = update_roles
    #     self.delete_roles = delete_roles

    @property
    def serialize(self):
        """Return object data in easily serializable format"""
        return {
            'id': self.id,
            'name': self.name,
            'group': self.group,
            'create_mails': self.create_mails,
            'update_mails': self.update_mails,
            'delete_mails': self.delete_mails,
            'create_users': self.create_users,
            'update_users': self.update_users,
            'delete_users': self.delete_users,
            'create_roles': self.create_roles,
            'update_roles': self.update_roles,
            'delete_roles': self.delete_roles,
            'created_at': self.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            'update_at': self.update_at.strftime("%Y-%m-%d %H:%M:%S")
        }

class Newsletter_status(str, enum.Enum):
    SENT = 1
    SCHEDULED = 2
    DRAFT = 3

class Newsletter(db.Model):
    __tablename__ = "newsletters"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    state = db.Column(Enum(Newsletter_status), nullable=False)
    deleted = db.Column(db.Boolean, default=False)
    publish = db.Column(db.DateTime, default=datetime.now)
    created_at = db.Column(db.DateTime, default=datetime.now)
    update_at = db.Column(db.DateTime, onupdate=datetime.now, default=datetime.now)

    @property
    def serialize(self):
        """Return object data in easily serializable format"""
        return {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'author': self.author,
            'state': Newsletter_status(self.state).name,
            'deleted': self.deleted,
            'publish': self.publish.strftime("%Y-%m-%d %H:%M:%S"),
            'created_at': self.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            'update_at': self.update_at.strftime("%Y-%m-%d %H:%M:%S")
        }

    # def __init__(self, title, content, author, publish=''):
    #     self.title = title
    #     self.content = content
    #     self.author = author
    #     self.publish = publish

class Registration_code(db.Model):
    __tablename__ = "registration_codes"
    id = db.Column(db.Integer, primary_key=True)
    account = db.Column(db.String(128), nullable=False, comment="mail")
    inviter = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    # token = db.Column(db.String, nullable=False)
    # available_time = db.Column(db.DateTime, default=datetime.now)
    created_at = db.Column(db.DateTime, default=datetime.now)
    update_at = db.Column(db.DateTime, onupdate=datetime.now, default=datetime.now)

    # def __init__(self, account, inviter, token, available_time):
    #     self.account = account
    #     self.inviter = inviter
    #     self.token = token
    #     self.available_time = available_time

    @property
    def serialize(self):
        """Return object data in easily serializable format"""
        return {
            'id': self.id,
            'account': self.account,
            'inviter': self.inviter,
            'created_at': self.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            'update_at': self.update_at.strftime("%Y-%m-%d %H:%M:%S")
        }

# todo: log database

def create_db():
    """Creates the db tables."""
    db.create_all()
def drop_db():
    """Drops the db tables."""
    db.drop_all()


def db_init():
    permissions_admin ={
        'create_mails':True,
        'update_mails':True,
        'delete_mails':True,
        'create_users':True,
        'update_users':True,
        'delete_users':True,
        'create_roles':True,
        'update_roles':True,
        'delete_roles':True
    }
    permissions_test = {
        'create_mails':True,
        'update_mails':True,
        'delete_mails':True
    }
    role_admin = Role(name="admin", group="admin", **permissions_admin)
    role_writer = Role(name="writer", group="writer", **permissions_test)
    admin = User(name="admin", account="admin@example.com", password=generate_password_hash("admin"), role=1)
    test = User(name="test", account="test@example.com", password=generate_password_hash("test"), role=2)
    db.session.add_all([role_admin, role_writer])
    db.session.add_all([admin, test])

    newsletter_test1 = Newsletter(title="test", content="newsletter1", author=1, state=Newsletter_status.DRAFT)
    newsletter_test2 = Newsletter(title="test", content="newsletter2", author=2, state=Newsletter_status.DRAFT)
    db.session.add_all([newsletter_test1, newsletter_test2])

    db.session.commit()
    print("db initialized")

# routes =================================================================
# for testing
@app.route("/")
def index():
    return "Hello World"

@app.route("/json")
def json():
    return request.get_json()

@app.route("/data")
def data():
    return request.data

@app.route("/form")
def form():
    return request.form


@app.route("/database/refresh")
def refresh_database():
    drop_db()
    create_db()
    db_init()
    return jsonify({'message': 'database refreshed'}), 200

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': 'Not found'}), 404


# users
@app.route("/users", methods=["POST"])
def create_user():
    request_json = request.get_json()
    user = User(**request_json)
    db.session.add(user)
    db.session.commit()
    return jsonify(user.serialize), 201

@app.route("/users", methods=["GET"])
def get_users():
    users = User.query.all()
    return jsonify([i.serialize for i in users]), 200

@app.route("/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    user = User.query.get_or_404(user_id)
    return jsonify(user.serialize), 200

@app.route("/users/<int:user_id>", methods=["PATCH"])
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    request_json = request.get_json()
    for key, value in request_json.items():
        if key == "account":
            continue
        if key == "password":
            user.password = generate_password_hash(value)
        setattr(user, key, value)
    db.session.commit()
    return ('', 204)

@app.route("/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    user.deleted = True
    db.session.commit()
    return ('', 204)


# roles
@app.route("/roles", methods=["POST"])
def create_role():
    request_json = request.get_json()
    role = Role(**request_json)
    db.session.add(role)
    db.session.commit()
    return jsonify(role.serialize), 201

@app.route("/roles", methods=["GET"])
def get_roles():
    roles = Role.query.all()
    return jsonify([i.serialize for i in roles]), 200

@app.route("/roles/<int:role_id>", methods=["GET"])
def get_role(role_id):
    role = Role.query.get_or_404(role_id)
    return jsonify(role.serialize), 200

@app.route("/roles/<int:role_id>", methods=["PATCH"])
def update_role(role_id):
    role = Role.query.get_or_404(role_id)
    request_json = request.get_json()
    for key, value in request_json.items():
        setattr(role, key, value)
    db.session.commit()
    return ('', 204)

@app.route("/roles/<int:role_id>", methods=["DELETE"])
def delete_role(role_id):
    role = Role.query.get_or_404(role_id)
    db.session.delete(role)
    db.session.commit()
    return ('', 204)

# newsletters
@app.route("/newsletters", methods=["POST"])
def create_newsletter():
    request_json = request.get_json()
    newsletter = Newsletter(**request_json)
    db.session.add(newsletter)
    db.session.commit()
    return jsonify(newsletter.serialize), 201

@app.route("/newsletters", methods=["GET"])
def get_newsletters():
    newsletters = Newsletter.query.order_by(Newsletter.id.desc()).all()
    return jsonify([i.serialize for i in newsletters])

@app.route("/newsletters/<int:newsletter_id>", methods=["GET"])
def get_newsletter(newsletter_id):
    newsletter = Newsletter.query.get_or_404(newsletter_id)
    return jsonify(newsletter.serialize), 200

@app.route("/newsletters/<string:state>", methods=["GET"])
def get_newsletter_by_state(state):
    newsletters = Newsletter.query.filter_by(state=state).order_by(Newsletter.id.desc()).all()
    return jsonify([i.serialize for i in newsletters]), 200

@app.route("/newsletters/<int:newsletter_id>", methods=["PATCH"])
def update_newsletter(newsletter_id):
    newsletter = Newsletter.query.get_or_404(newsletter_id)
    request_json = request.get_json()
    for key, value in request_json.items():
        setattr(newsletter, key, value)
    db.session.commit()
    return ('', 204)

@app.route("/newsletters/<int:newsletter_id>", methods=["DELETE"])
def delete_newsletter(newsletter_id):
    newsletter = Newsletter.query.get_or_404(newsletter_id)
    newsletter.deleted = True
    db.session.commit()
    return ('', 204)


# registration codes
@app.route("/registration-codes", methods=["POST"])
def create_registration_code():
    request_json = request.get_json()
    code = Registration_code(**request_json)
    db.session.add(code)
    db.session.commit()
    return jsonify(code.serialize), 201

@app.route("/registration-codes", methods=["GET"])
def get_registration_codes():
    codes = Registration_code.query.order_by(Registration_code.id.desc()).all()
    return jsonify([i.serialize for i in codes])

@app.route("/registration-codes/<int:code_id>", methods=["GET"])
def get_registration_code(code_id):
    code = Registration_code.query.get_or_404(code_id)
    return jsonify(code.serialize), 200

@app.route("/registration-codes/validation", methods=["PUT"])
def validate_registration_code():
    return "Hello World"

@app.route("/registration-codes/<int:code_id>", methods=["DELETE"])
def delete_registration_code(code_id):
    code = Registration_code.query.get_or_404(code_id)
    db.session.delete(code)
    db.session.commit()
    return ('', 204)


# auth
@app.route("/login", methods=["PUT"])
def login():
    return "Hello World"

@app.route("/logout", methods=["PUT"])
def logout():
    return "Hello World"
