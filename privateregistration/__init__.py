from . import plugin

from .register import private_register

from CTFd import utils


def load(app):
    app.db.create_all()

    if not utils.get_config('private_registration_option'):
        utils.set_config('private_registration_option', 'token')

    plugin.route(app)
    plugin.override_register_template()
    app.view_functions['auth.register'] = private_register
