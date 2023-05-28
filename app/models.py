from datetime import datetime
import enum
from sqlalchemy import Enum
from sqlalchemy.dialects import mysql
from app.extensions import db

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


class NewsletterState(enum.Enum):
    SENT = 1
    SCHEDULED = 2
    DRAFT = 3


class Newsletter(db.Model):
    __tablename__ = "newsletters"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), nullable=False)
    content = db.Column(mysql.MEDIUMTEXT, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    state = db.Column(Enum(NewsletterState), nullable=False)
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
            "state": NewsletterState(self.state).name,
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
                newsletter["state"] = NewsletterState(newsletter["state"]).name

        return newsletters


# todo: log database