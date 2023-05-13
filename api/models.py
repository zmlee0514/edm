from datetime import datetime
from api import db
from werkzeug.security import generate_password_hash, check_password_hash

def init():
    from api import app
    with app.app_context():
        db.create_all()
        permissions_admin ={
            'create_mails':True,
            'update_mails':True,
            'delete_mails':True,
            'create_users':True,
            'delete_users':True,
            'create_roles':True,
            'update_roles':True,
            'delete_roles':True
        }
        permissions_test = {
            'create_mails':True,
            'update_mails':True,
            'delete_mails':True,
            'create_users':False,
            'delete_users':False,
            'create_roles':False,
            'update_roles':False,
            'delete_roles':False
        }
        role_admin = Role("admin", "admin", **permissions_admin)
        role_test = Role("test", "test", **permissions_test)
        admin = User("admin", "admin@example.com", generate_password_hash("admin"), 1)
        test = User("test", "test@example.com", generate_password_hash("test"), 2)

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    account = db.Column(db.String(128), unique=True, nullable=False, comment="mail")
    password = db.Column(db.String(64), nullable=False)
    role = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    update_at = db.Column(db.DateTime, onupdate=datetime.now, default=datetime.now)

    # foreign key
    mail = db.relationship('Mail', backref='users')
    code = db.relationship('Registration_code', backref='users')

    def __init__(self, name, account, password, role):
        self.name = name
        self.account = account
        self.password = password
        self.role = role

class Role(db.Model):
    __tablename__ = "roles"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=True)
    group = db.Column(db.String(64), nullable=True)
    create_mails = db.Column(db.Boolean, default=False)
    update_mails = db.Column(db.Boolean, default=False)
    delete_mails = db.Column(db.Boolean, default=False)
    create_users = db.Column(db.Boolean, default=False)
    delete_users = db.Column(db.Boolean, default=False)
    create_roles = db.Column(db.Boolean, default=False)
    update_roles = db.Column(db.Boolean, default=False)
    delete_roles = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    update_at = db.Column(db.DateTime, onupdate=datetime.now, default=datetime.now)

    # foreign key
    user = db.relationship('User', backref='roles')

    def __init__(
        self,
        name='',
        group='',
        create_mails=False,
        update_mails=False,
        delete_mails=False,
        create_users=False,
        delete_users=False,
        create_roles=False,
        update_roles=False,
        delete_roles=False,
    ):
        self.name = name
        self.group = group
        self.create_mails = create_mails
        self.update_mails = update_mails
        self.delete_mails = delete_mails
        self.create_users = create_users
        self.delete_users = delete_users
        self.create_roles = create_roles
        self.update_roles = update_roles
        self.delete_roles = delete_roles

class Mail(db.Model):
    __tablename__ = "mails"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    publish = db.Column(db.DateTime, default=datetime.now)
    created_at = db.Column(db.DateTime, default=datetime.now)
    update_at = db.Column(db.DateTime, onupdate=datetime.now, default=datetime.now)

    def __init__(self, title, content, author, publish):
        self.title = title
        self.content = content
        self.author = author
        self.publish = publish

class Registration_code(db.Model):
    __tablename__ = "registration_codes"
    id = db.Column(db.Integer, primary_key=True)
    account = db.Column(db.String(128), nullable=False, comment="mail")
    inviter = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    # token = db.Column(db.String, nullable=False)
    available_time = db.Column(db.DateTime, default=datetime.now)
    created_at = db.Column(db.DateTime, default=datetime.now)
    update_at = db.Column(db.DateTime, onupdate=datetime.now, default=datetime.now)

    def __init__(self, account, inviter, token, available_time):
        self.account = account
        self.inviter = inviter
        self.token = token
        self.available_time = available_time

# todo: log database
