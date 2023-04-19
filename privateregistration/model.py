from CTFd.models import db


class InvitedTeams(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True)
    email = db.Column(db.String(128), unique=True)
    token = db.Column(db.String(32), unique=True)
    registered_id = db.Column(db.Integer)

    def __init__(self, name, email, token):
        self.name = name
        self.email = email
        self.token = token
