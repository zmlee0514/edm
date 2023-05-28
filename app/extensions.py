from flask_sqlalchemy import SQLAlchemy
from flask_redis import FlaskRedis
from flask_mail import Mail
from flask_apscheduler import APScheduler
from flask_jwt_extended import JWTManager
from itsdangerous import URLSafeTimedSerializer

db = SQLAlchemy()
redis = FlaskRedis()
jwt = JWTManager()
mailer = Mail()
scheduler = APScheduler()
# serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

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

def initialize_extensions(app):
    db.init_app(app)
    mailer.init_app(app)
    jwt.init_app(app)
    scheduler.init_app(app)
    # initialize_scheduler(scheduler)
    redis.init_app(app)

def get_serializer(app):
    return URLSafeTimedSerializer(app.config['SECRET_KEY'])