import os
import time
from datetime import datetime, timedelta
# from uuid import uuid4
from PIL import Image
from flask import Blueprint, current_app, jsonify, render_template, request
from flask_jwt_extended import (
    get_jwt_identity, get_jwt, jwt_required,
    create_access_token, create_refresh_token
)
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import User, Role, Newsletter, NewsletterState
from app.extensions import db, redis, jwt, scheduler, get_serializer
from app.mailer import send_email_with_newsletter, send_email_with_components

user_bp = Blueprint("user", __name__)
role_bp = Blueprint("role", __name__)
newsletter_bp = Blueprint("newsletter", __name__)
registration_bp = Blueprint("registration", __name__)
auth_bp = Blueprint("auth", __name__)
error_bp = Blueprint("error", __name__)

def register_blueprintes(app):
    app.register_blueprint(user_bp)
    app.register_blueprint(role_bp)
    app.register_blueprint(newsletter_bp)
    app.register_blueprint(registration_bp)
    app.register_blueprint(error_bp)

# Recording Query Information
# This feature is intended for debugging only.
# To enable this feature, set SQLALCHEMY_RECORD_QUERIES to True in the Flask app config.
# Use get_recorded_queries() to get a list of query info objects. Each object has the following attributes:
# statement
# parameters
# start_time / end_time
# duration
# location

@error_bp.app_errorhandler(404)
def not_found_error(error):
    return jsonify({"error": "Not found"}), 404

# You may see uses of Model.query or session.query to build queries.
# That query interface is considered legacy in SQLAlchemy.
# Prefer using the session.execute(select(...)) instead.
# users
@user_bp.route("/users", methods=["POST"])
def create_user():
    request_json = request.get_json()
    user = User(name=request_json["name"], account=request_json["account"], role_id=request_json["role_id"])
    user.password = generate_password_hash(request_json["password"])
    db.session.add(user)
    db.session.commit()
    return jsonify(user.serialize), 201

# page = db.paginate(db.select(User).order_by(User.join_date))
@user_bp.route("/users", methods=["GET"])
def get_users():
    order = request.args.get("order", "id")
    offset = request.args.get("offset", 0)
    limit = request.args.get("limit", 10)
    users = User.query.filter_by(deleted=False)
    total = users.count()
    users = users.order_by(order).offset(offset).limit(limit).all()
    return jsonify(users=[i.serialize for i in users], total=total), 200

@user_bp.route("/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    user = User.query.get_or_404(user_id)
    return jsonify(user.serialize), 200

@user_bp.route("/users/<int:user_id>", methods=["PATCH"])
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

@user_bp.route("/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    user.deleted = True
    db.session.commit()
    return ("", 204)


# roles
@role_bp.route("/roles", methods=["POST"])
def create_role():
    request_json = request.get_json()
    role = Role(**request_json)
    db.session.add(role)
    db.session.commit()
    return jsonify(role.serialize), 201

@role_bp.route("/roles", methods=["GET"])
def get_roles():
    roles = Role.query.all()
    return jsonify([i.serialize for i in roles]), 200

@role_bp.route("/roles/<int:role_id>", methods=["GET"])
def get_role(role_id):
    role = Role.query.get_or_404(role_id)
    return jsonify(role.serialize), 200

@role_bp.route("/roles/<int:role_id>", methods=["PATCH"])
def update_role(role_id):
    role = Role.query.get_or_404(role_id)
    request_json = request.get_json()
    for key, value in request_json.items():
        setattr(role, key, value)
    db.session.commit()
    return ("", 204)

@role_bp.route("/roles/<int:role_id>", methods=["DELETE"])
def delete_role(role_id):
    role = Role.query.get_or_404(role_id)
    db.session.delete(role)
    db.session.commit()
    return ("", 204)


# newsletters
@newsletter_bp.route("/newsletters", methods=["POST"])
def create_newsletter():
    request_json = request.get_json()
    if 'state' not in request_json:
        request_json["state"] = "DRAFT"
    if request_json["state"] not in NewsletterState.__members__:
        return jsonify({"error": "invalid state"}), 400
    if NewsletterState[request_json["state"]] is NewsletterState.SENT:
        return jsonify({"error": "SENT state can not be specified"}), 400
    newsletter = Newsletter(**request_json)
    db.session.add(newsletter)
    db.session.commit()
    if newsletter.state is NewsletterState.SCHEDULED:
        publish = newsletter.publish+timedelta(minutes=1)
        if publish < datetime.now():
            newsletter.state = NewsletterState.DRAFT
            db.session.commit()
        else:
            scheduler.add_job(func=send_email_with_newsletter, id=str(newsletter.id), trigger='date', run_date=publish, args=[(current_app.config["MAIL_SENDER_NAME"], current_app.config["MAIL_USERNAME"]), newsletter.id])
            print(f"scheduled newsletter {newsletter.id}")
    return jsonify(newsletter.serialize), 201

@newsletter_bp.route("/newsletters", methods=["GET"])
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


@newsletter_bp.route("/newsletters/<int:newsletter_id>", methods=["GET"])
def get_newsletter(newsletter_id):
    newsletter = Newsletter.query.get_or_404(newsletter_id)
    return jsonify(newsletter.serialize), 200


@newsletter_bp.route("/newsletters/search", methods=["GET"])
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


@newsletter_bp.route("/newsletters/<int:newsletter_id>", methods=["PATCH"])
def update_newsletter(newsletter_id):
    newsletter = Newsletter.query.get_or_404(newsletter_id)
    job_id = str(newsletter_id)
    if newsletter.state is NewsletterState.SENT:
        return jsonify({"error": "Sent newsletter can not be modified"}), 403
    elif newsletter.state is NewsletterState.SCHEDULED and scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
        print(f"removed scheduled newsletter {newsletter_id}")

    request_json = request.get_json()
    if 'state' not in request_json:
        request_json["state"] = "DRAFT"
    if request_json["state"] not in NewsletterState.__members__:
        return jsonify({"error": "invalid state"}), 400
    if NewsletterState[request_json["state"]] is NewsletterState.SENT:
        return jsonify({"error": "SENT state can not be specified"}), 400

    for key, value in request_json.items():
        setattr(newsletter, key, value)
    if newsletter.state is NewsletterState.SCHEDULED:
        publish = newsletter.publish+timedelta(minutes=1)
        if publish < datetime.now():
            newsletter.state = NewsletterState.DRAFT
        else:
            scheduler.add_job(func=send_email_with_newsletter, id=job_id, trigger='date', run_date=publish, args=[(current_app.config["MAIL_SENDER_NAME"], current_app.config["MAIL_USERNAME"]), newsletter_id])
            print(f"scheduled newsletter {newsletter_id}")
    db.session.commit()
    return ("", 204)


@newsletter_bp.route("/newsletters/<int:newsletter_id>", methods=["DELETE"])
def delete_newsletter(newsletter_id):
    newsletter = Newsletter.query.get_or_404(newsletter_id)
    newsletter.deleted = True
    if newsletter.state == NewsletterState.SCHEDULED:
        if scheduler.get_job(str(newsletter_id)):
            scheduler.remove_job(str(newsletter_id))
            print(f"removed scheduled newsletter {newsletter_id}")
        newsletter.state = NewsletterState.DRAFT
    db.session.commit()
    return ("", 204)

# upload images
@newsletter_bp.route('/newsletters/images/upload', methods=['POST'])
def upload_file():
    if 'image' not in request.files:
        return jsonify({"error": "No file found"}), 400
    file = request.files['image']
    if not file.filename or '.' not in file.filename:
        return jsonify({"error": "Invalid file"}), 400
    file_ext = file.filename.rsplit('.', 1)[1].lower()
    if file_ext not in current_app.config["ALLOWED_UPLOAD_IMAGE_EXTENSIONS"]:
        return jsonify({"error": "Invalid file type"}), 400
    webp_filename = f"{os.urandom(32).hex()}.webp"
    while os.path.exists(webp_filename):
        webp_filename = f"{os.urandom(32).hex()}.webp"
    webp_file_path = os.path.join(os.getcwd(), "app", "uploads", "newsletters", "images", webp_filename)
    os.makedirs(os.path.dirname(webp_file_path), exist_ok=True)
    image = Image.open(file.read())
    image.save(webp_file_path, 'WebP')

    return {'file_path':webp_file_path[13:]}, 200


# auth
@auth_bp.route('/register', methods=['POST'])
def register():
    request_json = request.get_json()
    if "token" not in request_json:
        return jsonify({"error": "token is required"}), 400
    ret, code = verify_registration_code(request_json["token"])
    if code != 200:
        return ret, code
    redis.delete(request_json["token"])
    return create_user()

@auth_bp.route("/login", methods=["POST"])
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
        'role_id': user.role_id
    }
    access_token = create_access_token(identity=user.id, additional_claims=additional_claims)
    refresh_token = create_refresh_token(identity=user.id, additional_claims=additional_claims)
    return jsonify(user=user.serialize, access_token=access_token, refresh_token=refresh_token), 200

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    user_id = get_jwt_identity()
    claims = {k:v for k,v in get_jwt().items() if k in {"user_id", "name", "role_id"}}
    access_token = create_access_token(identity=user_id, additional_claims=claims)
    return jsonify(access_token=access_token), 200

@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload: dict):
    jti = jwt_payload["jti"]
    token_in_blacklist = redis.get(jti)
    return token_in_blacklist is not None

@auth_bp.route("/logout", methods=["DELETE"])
@jwt_required(refresh=True)
def logout():
    refresh_token = get_jwt()
    jti = refresh_token["jti"]
    exp = refresh_token["exp"]
    redis.set(jti, 1, ex=int(exp-time.time()))
    print("add revoked token:", jti)
    return ('', 204)

# for testing
@auth_bp.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


# registration mail
@registration_bp.route("/registrations", methods=["POST"])
def create_registration_code():
    request_json = request.get_json()
    token = get_serializer(current_app).dumps(request_json["email"], salt=current_app.config['SECURITY_PASSWORD_SALT'])
    redis.set(token, request_json["email"], ex=3600)
    link = f"https://{current_app.config['DOMAIN']}/register?token={token}"
    html = render_template("template-mail-register.html", account=request_json["email"], link=link)
    scheduler.add_job(id=f"send_invitation_{request_json['email']}", func=send_email_with_components, args=[(current_app.config["MAIL_SENDER_NAME"], current_app.config["MAIL_USERNAME"]), [request_json["email"]], "技職大玩JOB後台註冊邀請", html], trigger='date', run_date=datetime.now())
    # send_email_with_components([request_json["email"]], "技職大玩JOB後台註冊邀請", html)
    return {"msg": "Verification email sent"}, 201

@registration_bp.route("/registrations/verify/<token>", methods=["GET"])
def verify_registration_code(token):
    try:
        email = get_serializer(current_app).loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'], max_age=current_app.config["INVITATION_EMAIL_EXPIRE_SECONDS"])
        if not redis.exists(token):
            return {"msg": "The token has already been used"}, 401
        return {'email':email}, 200
    except:
        return {'msg':'Invalid or expired token'}, 401
