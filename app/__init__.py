import os
from flask import Flask
from app.extensions import initialize_extensions
from app.api import register_blueprintes

def create_app(config_name = ''):
    edm_env = config_name if config_name else os.environ.get("FLASK_ENV", "Development")
    if edm_env not in ["Development", "Testing", "Production"]:
        raise ValueError("invalid environment: {}".format(edm_env))

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_pyfile(f"{app.instance_path}/BaseConfig.py")
    app.config.from_pyfile(f"{app.instance_path}/{edm_env}Config.py")

    initialize_extensions(app)
    register_blueprintes(app)

    return app

# database =================================================================
# def get_db():
#     db = getattr(g, '_database', None)
#     if db is None:
#         db = g._database = sqlite3.connect(DATABASE)
#     return db

# @app.teardown_appcontext
# def close_connection(exception):
#     db = getattr(g, '_database', None)
#     if db is not None:
#         db.close()

# def init_db():
#     with app.app_context():
#         db = get_db()
#         with app.open_resource('schema.sql', mode='r') as f:
#             db.cursor().executescript(f.read())
#         db.commit()

# $ from yourapplication import init_db
# $ init_db()

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


# def initialize_scheduler(scheduler):
#     with scheduler.app.app_context():
#         unscheduled_newsletters = Newsletter.query.filter_by(state=Newsletter_state.SCHEDULED).all()
#         now = datetime.now()
#         count = 0
#         for newsletter in unscheduled_newsletters:
#             # if the newsletter should be sent when the server shuts down, send it now
#             if newsletter.publish < now:
#                 newsletter.publish = now.strftime("%Y-%m-%d %H:%M:%S")
#                 scheduler.add_job(func=send_email_with_newsletter, id=str(newsletter.id), trigger='date', run_date=now+timedelta(minutes=1), args=[newsletter.id])
#             else:
#                 scheduler.add_job(func=send_email_with_newsletter, id=str(newsletter.id), trigger='date', run_date=newsletter.publish+timedelta(minutes=1), args=[newsletter.id])
#             count += 1
#         print(f"scheduler initialized with {count} unscheduled newsletters")
#         db.session.commit()