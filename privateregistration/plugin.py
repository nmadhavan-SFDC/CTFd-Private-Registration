from flask import jsonify, request, send_file, url_for

from os import path

from .invitation import add_to_invitation_list, get_invited_teams_csv
from .model import InvitedTeams
from .register import private_register

from CTFd.models import db, Teams
from CTFd import utils
from CTFd.utils.decorators import admins_only
from CTFd.cache import cache
from CTFd.utils.plugins import override_template

def override_register_template():
    dir_path = path.dirname(path.realpath(__file__))
    template_path = dir_path + '/templates/private-registration.html'

    with open(template_path, 'r') as register_template:
        override_template('register.html', register_template.read())


def route(app):
    @app.route('/admin/invited_teams/', methods=['GET'])
    @admins_only
    def get_invited_teams():
        teams = Teams.query.add_columns('id').all()

        registered_teams = {}
        for team in teams:
            registered_teams[team.id] = True

        invited_teams = InvitedTeams.query.order_by(InvitedTeams.id.asc()).all()

        json = {'invited_teams': []}
        for team in invited_teams:
            if team.registered_id in registered_teams:
                registered = True
            else:
                registered = False
            json['invited_teams'].append(
                {'id': team.id, 'name': team.name, 'email': team.email,
                 'token': team.token, 'registered': registered})

        return jsonify(json)


    @app.route('/admin/invited_teams/delete/<int:id>', methods=['POST'])
    @admins_only
    def delete_invited_team(id):
        try:
            InvitedTeams.query.filter_by(id=id).delete()
            db.session.commit()
            db.session.close()
        except DatabaseError:
            return '0'
        else:
            return '1'


    @app.route('/admin/invited_teams/delete/all', methods=['POST'])
    @admins_only
    def remove_all_invited_teams():
        try:
            InvitedTeams.query.delete()
            db.session.commit()
            db.session.close()
        except DatabaseError:
            return '0'
        else:
            return '1'


    @app.route('/admin/invited_teams/export', methods=['GET'])
    @admins_only
    def export_csv():
        output = get_invited_teams_csv()
        ctf_name = utils.ctf_name()
        full_name = '{}-invited-teams.csv'.format(ctf_name)
        return send_file(output, as_attachment=True,
                         attachment_filename=full_name)


    @app.route('/admin/invited_teams/import', methods=['POST'])
    @admins_only
    def import_csv():
        if 'invited_teams' in request.files:
            csv_file = request.files['invited_teams']
            messages, errors = add_to_invitation_list(csv_file)
            json = {'messages': messages, 'errors': errors}
            return jsonify(json)
        else:
            return '0'


    @app.route('/admin/invited_teams/option', methods=['POST'])
    @admins_only
    def set_option():
        with app.app_context():
            cache.clear()
        selected_option = request.form.get('selected_option', None)
        if selected_option:
            utils.set_config('private_registration_option', selected_option)
            return '1'
        else:
            return '0'


    @app.route('/admin/invited_teams/send_invitation', methods=['POST'])
    @admins_only
    def send_invitation_all():
        if utils.can_send_mail():
            selected_option = utils.get_config('private_registration_option')
            teams = Teams.query.add_columns('name').all()
            registered_teams = {}

            for team in teams:
                registered_teams[team.name] = True

            invited_teams = InvitedTeams.query.order_by(
                InvitedTeams.id.asc()).all()

            for team in invited_teams:
                if team.name in registered_teams:
                    continue
                if selected_option == 'token':
                    token_text = ' with token {}'.format(team.token)
                else:
                    token_text = ''
                text = 'Team {} ({}) is invited for {}. You can register ' \
                       'in {}{}.'.format(
                    team.name,
                    team.email,
                    utils.get_config('ctf_name'),
                    url_for('auth.register', _external=True),
                    token_text
                )
                utils.sendmail(team.email, text)
            return '1'
        else:
            return '0'


    @app.route('/admin/invited_teams/send_invitation/<int:id>',
               methods=['POST'])
    @admins_only
    def send_invitation(id):
        if utils.can_send_mail():
            selected_option = utils.get_config('private_registration_option')
            team = InvitedTeams.query.add_columns(
                'name', 'email', 'token').filter_by(id=id).first()

            if selected_option == 'token':
                token_text = ' with token {}'.format(team.token)
            else:
                token_text = ''
            text = 'Team {} ({}) is invited for {}. You can register ' \
                   'in {}{}.'.format(
                team.name,
                team.email,
                utils.get_config('ctf_name'),
                url_for('auth.register', _external=True),
                token_text
            )

            utils.sendmail(team.email, text)
            return '1'
        else:
            return '0'
