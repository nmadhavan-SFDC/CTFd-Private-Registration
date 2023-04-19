import csv
import io
import re
import sys

from hashlib import md5
from os import path, urandom

from .model import InvitedTeams

from CTFd.models import db, Teams


def add_to_invitation_list(csv_file):
    if sys.version_info[0] >= 3:  # We need to support Python 3 bytes
        team_list = str(csv_file.read(), 'utf-8').splitlines()
    else:
        team_list = csv_file.read().splitlines()

    team_list = list(csv.reader(team_list))
    messages = []
    errors = []

    line_no = 0
    number_of_invited_teams = 0

    for team in team_list:
        line_no += 1

        if len(team) != 2:
            if len(team) != 0:
                errors.append('Invalid number of fields on line %d' % line_no)
            continue

        name = team[0]
        email = team[1]

        if sys.version_info[0] < 3:  # Support unicode for Python 2
            name = name.decode('utf-8')

        name_len = len(name) == 0
        valid_email = re.match(
            r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", email)
        registered_names = Teams.query.add_columns('name').filter_by(
            name=name).first()
        registered_emails = Teams.query.add_columns('email').filter_by(
            email=email).first()
        invited_names = InvitedTeams.query.add_columns('name').filter_by(
            name=name).first()
        invited_emails = InvitedTeams.query.add_columns('email').filter_by(
            email=email).first()

        # To check if there are any additional errors later
        errors_len = len(errors)

        if name_len:
            errors.append('Invalid team name on line %d' % line_no)
        if not valid_email:
            errors.append('Invalid email on line %d' % line_no)
        if registered_names:
            errors.append('Already registered team name on line %d' % line_no)
        if registered_emails:
            errors.append('Already registered email on line %d' % line_no)
        if invited_names:
            errors.append('Already invited team name on line %d' % line_no)
        if invited_emails:
            errors.append('Already invited email on line %d' % line_no)

        if len(errors) == errors_len:  # No additional errors at this point
            token = md5(urandom(64)).hexdigest()
            invited_team = InvitedTeams(name, email, token)
            db.session.add(invited_team)
            number_of_invited_teams += 1

    db.session.commit()
    db.session.close()

    if number_of_invited_teams > 0:
        messages.append('Succesfully added %d teams to invitation list'
                        % number_of_invited_teams)

    return messages, errors


def get_invited_teams_csv():
    # Hack to support in-memory IO stream both in Python 2 & Python 3
    if sys.version_info[0] >= 3:
        output = io.StringIO()
    else:
        output = io.BytesIO()

    writer = csv.writer(output)
    invited_teams = InvitedTeams.query.order_by(InvitedTeams.id.asc()).all()
    writer.writerow(['team_name', 'team_email', 'token'])

    for team in invited_teams:
        writer.writerow([team.name, team.email, team.token])

    if sys.version_info[0] >= 3:  # We need to convert IO to BytesIO in Python 3
        bytes_output = io.BytesIO()
        bytes_output.write(output.getvalue().encode('utf-8'))
        output = bytes_output

    output.seek(0)
    return output
