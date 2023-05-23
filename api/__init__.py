from datetime import datetime, timedelta
from collections import OrderedDict
from uuid import uuid4
from PIL import Image
import time
import enum
import os
import smtplib
from flask import Flask, jsonify, render_template, request
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_apscheduler import APScheduler
from flask_jwt_extended import (
    JWTManager, get_jwt_identity, get_jwt,
    jwt_required, create_access_token, create_refresh_token
)
from sqlalchemy import Enum
from sqlalchemy.dialects import mysql
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import import_string
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
edm_env = os.environ.get("FLASK_ENV", "Development")
cfg = import_string(f"config.{edm_env}Config")()
app.config.from_object(cfg)

db = SQLAlchemy(app)
mail = Mail(app)
jwt = JWTManager(app)
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

revoked_tokens = set()
revoked_tokens_sort_by_exp = OrderedDict()

# database =================================================================
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    account = db.Column(db.String(128), unique=True, nullable=False, comment="mail")
    password = db.Column(db.String(128), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)
    deleted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, onupdate=datetime.now, default=datetime.now)

    # foreign key
    role = db.relationship("Role", backref="users")

    @property
    def serialize(self):
        """Return object data in easily serializable format"""
        return {
            "id": self.id,
            "name": self.name,
            "account": self.account,
            "role_id": self.role_id,
            "deleted": self.deleted,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "updated_at": self.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
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
    updated_at = db.Column(db.DateTime, onupdate=datetime.now, default=datetime.now)

    @property
    def serialize(self):
        """Return object data in easily serializable format"""
        return {
            "id": self.id,
            "name": self.name,
            "group": self.group,
            "create_mails": self.create_mails,
            "update_mails": self.update_mails,
            "delete_mails": self.delete_mails,
            "create_users": self.create_users,
            "update_users": self.update_users,
            "delete_users": self.delete_users,
            "create_roles": self.create_roles,
            "update_roles": self.update_roles,
            "delete_roles": self.delete_roles,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "updated_at": self.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
        }


class Newsletter_state(enum.Enum):
    SENT = enum.auto()
    SCHEDULED = enum.auto()
    DRAFT = enum.auto()


class Newsletter(db.Model):
    __tablename__ = "newsletters"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), nullable=False)
    content = db.Column(mysql.MEDIUMTEXT, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    state = db.Column(Enum(Newsletter_state), nullable=False)
    deleted = db.Column(db.Boolean, default=False)
    publish = db.Column(db.DateTime, default=datetime.now)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, onupdate=datetime.now, default=datetime.now)

    user = db.relationship("User", backref="newsletters")

    @property
    def serialize(self):
        """Return object data in easily serializable format"""
        return {
            "id": self.id,
            "title": self.title,
            "content": self.content,
            "author_id": self.author_id,
            "state": Newsletter_state(self.state).name,
            "deleted": self.deleted,
            "publish": self.publish.strftime("%Y-%m-%d %H:%M:%S"),
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "updated_at": self.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
        }

    @classmethod
    def serialize_with_columns(cls, columns, data):
        """Return object data in easily serializable format"""
        if not data:
            return []

        newsletters = [dict(zip(columns, i)) for i in data]
        if "publish" in newsletters[0]:
            for newsletter in newsletters:
                newsletter["publish"] = newsletter["publish"].strftime("%Y-%m-%d %H:%M:%S")
        if "created_at" in newsletters[0]:
            for newsletter in newsletters:
                newsletter["created_at"] = newsletter["created_at"].strftime("%Y-%m-%d %H:%M:%S")
        if "updated_at" in newsletters[0]:
            for newsletter in newsletters:
                newsletter["updated_at"] = newsletter["updated_at"].strftime("%Y-%m-%d %H:%M:%S")
        if "state" in newsletters[0]:
            for newsletter in newsletters:
                newsletter["state"] = Newsletter_state(newsletter["state"]).name

        return newsletters


class Registration_code(db.Model):
    __tablename__ = "registration_codes"
    id = db.Column(db.Integer, primary_key=True)
    account = db.Column(db.String(128), nullable=False, comment="mail")
    inviter_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    # token = db.Column(db.String, nullable=False)
    # available_time = db.Column(db.DateTime, default=datetime.now)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, onupdate=datetime.now, default=datetime.now)

    user = db.relationship("User", backref="registration_codes")

    # def __init__(self, account, inviter, token, available_time):
    #     self.account = account
    #     self.inviter = inviter
    #     self.token = token
    #     self.available_time = available_time

    @property
    def serialize(self):
        """Return object data in easily serializable format"""
        return {
            "id": self.id,
            "account": self.account,
            "inviter_id": self.inviter_id,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "updated_at": self.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
        }


# todo: log database

# utils  =================================================================
def create_db():
    """Creates the db tables."""
    db.create_all()

def drop_db():
    """Drops the db tables."""
    db.drop_all()

def db_init():
    permissions_admin = {
        "create_mails": True,
        "update_mails": True,
        "delete_mails": True,
        "create_users": True,
        "update_users": True,
        "delete_users": True,
        "create_roles": True,
        "update_roles": True,
        "delete_roles": True,
    }
    permissions_test = {
        "create_mails": True,
        "update_mails": True,
        "delete_mails": True,
    }
    role_admin = Role(name="admin", group="admin", **permissions_admin)
    role_writer = Role(name="writer", group="writer", **permissions_test)
    admin = User(
        name="admin",
        account="admin@example.com",
        password=generate_password_hash("admin"),
        role_id=1,
    )
    writer = User(
        name="writer",
        account="writer@example.com",
        password=generate_password_hash("writer"),
        role_id=2,
    )
    Andy = User(
        name="Andy",
        account="koichiyamamoto@mindnodeair.com",
        password=generate_password_hash("koichiyamamoto"),
        role_id=1,
    )
    db.session.add_all([role_admin, role_writer])
    db.session.add_all([admin, writer, Andy])

    newsletter_test1 = Newsletter(
        title="test", content="newsletter1", author_id=1, state=Newsletter_state.DRAFT
    )
    newsletter_test2 = Newsletter(
        title="test", content="newsletter2", author_id=2, state=Newsletter_state.DRAFT
    )
    db.session.add_all([newsletter_test1, newsletter_test2])

    db.session.commit()
    print("db initialized")

# send mail
def send_email_with_newsletter(newsletter_id):
    with scheduler.app.app_context():
        newsletter = Newsletter.query.get(newsletter_id)
        send_email_with_components("技職大玩JOB電子報", [newsletter.user.account], newsletter.title, newsletter.content)
        newsletter.state = Newsletter_state.SENT
        db.session.commit()
    return "Email sent!"

def send_email_with_components(subject, recipients, title, content):
    try:
        msg = Message(
            subject, sender=(app.config["MAIL_SENDER_NAME"], app.config["MAIL_USERNAME"]), recipients=recipients
        )
        msg.html = render_template("template-news.html", title=title, content=content)
        mail.send(msg)
    except smtplib.SMTPException as e:
        return "Failed to send email: " + str(e)

def scheduler_init(scheduler):
    with scheduler.app.app_context():
        unscheduled_newsletters = Newsletter.query.filter_by(state=Newsletter_state.SCHEDULED).all()
        now = datetime.now()
        count = 0
        for newsletter in unscheduled_newsletters:
            # if the newsletter should be sent when the server shuts down, send it now
            if newsletter.publish < now:
                newsletter.publish = now.strftime("%Y-%m-%d %H:%M:%S")
                scheduler.add_job(func=send_email_with_newsletter, id=str(newsletter.id), trigger='date', run_date=now+timedelta(minutes=1), args=[newsletter.id])
            else:
                scheduler.add_job(func=send_email_with_newsletter, id=str(newsletter.id), trigger='date', run_date=newsletter.publish+timedelta(minutes=1), args=[newsletter.id])
            count += 1
        print(f"scheduler initialized with {count} unscheduled newsletters")
        db.session.commit()
scheduler_init(scheduler)

# routes =================================================================
# for testing
@app.route("/")
def index():
    return "Hello World"

@app.route("/send_test_email")
def send_test_email():
    send_email_with_components(
        "Test Email", ["leechengmin@mindnodeair.com"], "sample title", "test content"
    )
    return "Email sent!"

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
    return jsonify({"message": "database refreshed"}), 200

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({"error": "Not found"}), 404


# users
@app.route("/users", methods=["POST"])
def create_user():
    request_json = request.get_json()
    user = User(**request_json)
    user.password = generate_password_hash(user.password)
    db.session.add(user)
    db.session.commit()
    return jsonify(user.serialize), 201

@app.route("/users", methods=["GET"])
def get_users():
    order = request.args.get("order", "id")
    offset = request.args.get("offset", 0)
    limit = request.args.get("limit", 10)
    users = User.query.filter_by(deleted=False)
    total = users.count()
    users = users.order_by(order).offset(offset).limit(limit).all()
    return jsonify(users=[i.serialize for i in users], total=total), 200

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
    return ("", 204)

@app.route("/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    user.deleted = True
    db.session.commit()
    return ("", 204)


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
    return ("", 204)

@app.route("/roles/<int:role_id>", methods=["DELETE"])
def delete_role(role_id):
    role = Role.query.get_or_404(role_id)
    db.session.delete(role)
    db.session.commit()
    return ("", 204)


# newsletters
@app.route("/newsletters", methods=["POST"])
def create_newsletter():
    request_json = request.get_json()
    if 'state' not in request_json:
        request_json["state"] = "DRAFT"
    if request_json["state"] not in Newsletter_state.__members__:
        return jsonify({"error": "invalid state"}), 400
    if Newsletter_state[request_json["state"]] is Newsletter_state.SENT:
        return jsonify({"error": "SENT state can not be specified"}), 400
    newsletter = Newsletter(**request_json)
    db.session.add(newsletter)
    db.session.commit()
    if newsletter.state is Newsletter_state.SCHEDULED:
        publish = newsletter.publish+timedelta(minutes=1)
        if publish < datetime.now():
            newsletter.state = Newsletter_state.DRAFT
            db.session.commit()
        else:
            scheduler.add_job(func=send_email_with_newsletter, id=str(newsletter.id), trigger='date', run_date=publish, args=[newsletter.id])
            print(f"scheduled newsletter {newsletter.id}")
    return jsonify(newsletter.serialize), 201

@app.route("/newsletters", methods=["GET"])
def get_newsletters():
    offset = request.args.get("offset", 0)
    limit = request.args.get("limit", 10)
    newsletters = (
        Newsletter.query
        .filter_by(deleted=False)
        .with_entities(
            Newsletter.id,
            Newsletter.title,
            Newsletter.author_id,
            Newsletter.state,
            Newsletter.publish,
            Newsletter.created_at,
            Newsletter.updated_at
        )
    )
    total = newsletters.count()
    newsletters = newsletters.order_by(Newsletter.id.desc()).offset(offset).limit(limit).all()
    columns = ["id","title","author_id","state","publish","created_at","updated_at"]
    return jsonify(newsletters=Newsletter.serialize_with_columns(columns, newsletters), total=total), 200


@app.route("/newsletters/<int:newsletter_id>", methods=["GET"])
def get_newsletter(newsletter_id):
    newsletter = Newsletter.query.get_or_404(newsletter_id)
    return jsonify(newsletter.serialize), 200


@app.route("/newsletters/search", methods=["GET"])
def get_newsletters_by_state():
    offset = request.args.get("offset", 0)
    limit = request.args.get("limit", 10)
    state = request.args.get("state")
    title = request.args.get("title")
    newsletters = (
        Newsletter.query.with_entities(
            Newsletter.id,
            Newsletter.title,
            Newsletter.author_id,
            Newsletter.state,
            Newsletter.publish,
            Newsletter.created_at,
            Newsletter.updated_at
        )
        .filter_by(deleted=False)
    )
    if state:
        newsletters = newsletters.filter_by(state=state)
    if title:
        newsletters = newsletters.filter(Newsletter.title.like(f"%{title}%"))
    total = newsletters.count()
    newsletters = newsletters.order_by(Newsletter.id.desc()).offset(offset).limit(limit).all()
    columns = ["id","title","author_id","state","publish","created_at","updated_at"]
    return jsonify(newsletters=Newsletter.serialize_with_columns(columns, newsletters), total=total), 200


@app.route("/newsletters/<int:newsletter_id>", methods=["PATCH"])
def update_newsletter(newsletter_id):
    newsletter = Newsletter.query.get_or_404(newsletter_id)
    job_id = str(newsletter_id)
    if newsletter.state is Newsletter_state.SENT:
        return jsonify({"error": "Sent newsletter can not be modified"}), 403
    elif newsletter.state is Newsletter_state.SCHEDULED and scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
        print(f"removed scheduled newsletter {newsletter_id}")

    request_json = request.get_json()
    if 'state' not in request_json:
        request_json["state"] = "DRAFT"
    if request_json["state"] not in Newsletter_state.__members__:
        return jsonify({"error": "invalid state"}), 400
    if Newsletter_state[request_json["state"]] is Newsletter_state.SENT:
        return jsonify({"error": "SENT state can not be specified"}), 400

    for key, value in request_json.items():
        setattr(newsletter, key, value)
    if newsletter.state is Newsletter_state.SCHEDULED:
        publish = newsletter.publish+timedelta(minutes=1)
        if publish < datetime.now():
            newsletter.state = Newsletter_state.DRAFT
        else:
            scheduler.add_job(func=send_email_with_newsletter, id=job_id, trigger='date', run_date=publish, args=[newsletter_id])
            print(f"scheduled newsletter {newsletter_id}")
    db.session.commit()
    return ("", 204)


@app.route("/newsletters/<int:newsletter_id>", methods=["DELETE"])
def delete_newsletter(newsletter_id):
    newsletter = Newsletter.query.get_or_404(newsletter_id)
    newsletter.deleted = True
    if newsletter.state == Newsletter_state.SCHEDULED:
        scheduler.remove_job(str(newsletter_id))
        print(f"removed scheduled newsletter {newsletter_id}")
        newsletter.state = Newsletter_state.DRAFT
    db.session.commit()
    return ("", 204)

# upload images
@app.route('/newsletters/images/upload', methods=['POST'])
def upload_file():
    if 'image' not in request.files:
        return jsonify({"error": "No file found"}), 400

    file = request.files['image']
    if not file.filename or '.' not in file.filename:
        return jsonify({"error": "Invalid file"}), 400
    file_ext = file.filename.rsplit('.', 1)[1].lower()
    if file_ext not in app.config["ALLOWED_UPLOAD_IMAGE_EXTENSIONS"]:
        return jsonify({"error": "Invalid file type"}), 400
    uuid_filename = str(uuid4())
    webp_filename = f'{uuid_filename}.webp'
    webp_file_path = os.path.join(app.config["API_ROUTE_PREFIX"], app.config['UPLOAD_FOLDER'], "newsletters", "images", webp_filename)
    os.makedirs(os.path.dirname(webp_file_path), exist_ok=True)
    image = Image.open(file)
    image.save(webp_file_path, 'WebP')

    return {'file_path':webp_file_path[13:]}, 200


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
    return ("", 204)


# auth
@app.route("/login", methods=["POST"])
def login():
    request_json = request.get_json()
    if "account" not in request_json or "password" not in request_json:
        return jsonify({"error": "account and password are required"}), 400
    user = User.query.filter_by(account=request_json["account"]).first()
    if not user:
        return jsonify({"error": "account not found"}), 404
    if not check_password_hash(user.password, request_json["password"]):
        return jsonify({"error": "password is incorrect"}), 401

    additional_claims = {
        'user_id': user.id,
        'name': user.name,
        'role': user.role_id
    }
    access_token = create_access_token(identity=user.id, additional_claims=additional_claims)
    refresh_token = create_refresh_token(identity=user.id)
    return jsonify(user=user.serialize, jwt_token=access_token, refresh_token=refresh_token), 200

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    user_id = get_jwt_identity()
    user = User.query.filter_by(id=user_id).first()
    additional_claims = {
        'user_id': user.id,
        'name': user.name,
        'role': user.role_id
    }
    access_token = create_access_token(identity=user.id, additional_claims=additional_claims)
    return jsonify(jwt_token=access_token), 200

@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload: dict):
    jti = jwt_payload["jti"]
    return jti in revoked_tokens

@app.route("/logout", methods=["DELETE"])
@jwt_required(refresh=True)
def logout():
    # clean up expired tokens
    current_timestamp = time.time()
    for exp, jti_arr in revoked_tokens_sort_by_exp.items():
        if exp > current_timestamp:
            break
        for jti in jti_arr:
            revoked_tokens.remove(jti)
        removed_tokens = revoked_tokens_sort_by_exp.pop(exp)
        print("removed revoked tokens:", removed_tokens)

    refresh_token = get_jwt()
    jti = refresh_token["jti"]
    exp = refresh_token["exp"]
    revoked_tokens.add(jti)
    print("add revoked token:", jti)
    if exp in revoked_tokens_sort_by_exp:
        revoked_tokens_sort_by_exp[exp].append(jti)
    else:
        revoked_tokens_sort_by_exp[exp] = [jti]
    return ('', 204)

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200