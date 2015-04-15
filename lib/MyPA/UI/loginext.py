from functools import wraps
from flask import current_app, redirect, url_for
from flask.ext.login import current_user

def not_logged_in_required(func):
    """
    This provides a decorator that is the inverse of the flask-login
    login_required decorator.  i.e. if the user is logged in, the user is
    redirected to another page.
    """
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if current_app.login_manager._login_disabled:
            return func(*args, **kwargs)
        elif current_user.is_authenticated():
            # probably not great to hard-code this
            return redirect(url_for('account'))
        return func(*args, **kwargs)
    return decorated_view
