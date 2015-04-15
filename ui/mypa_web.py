
import os
from ConfigParser import ConfigParser

from flask import Flask, request, session, url_for, redirect, \
    render_template, flash

from flask.ext.kvsession import KVSessionExtension

from flask.ext.login import LoginManager, login_user, logout_user, \
    login_required, current_user

from flask.ext.wtf import Form, TextField, PasswordField, HiddenField

from MyPA.UI.forms import *
from MyPA.UI.loginext import not_logged_in_required
from MyPA.UI.session import load_session_store

from pprint import pprint

app = Flask(__name__)

conf_file = "/etc/MyPA/ui.ini"
conf = ConfigParser()
conf.read(conf_file)

# Replace the default flask session system with a server-side one
store = load_session_store(conf)
KVSessionExtension(store, app)
# We're not using the default session system, but this still needs to be
# set.  The server-side session key is stored encrypted in the browser
# session cookie.
app.secret_key = conf.get('ui', 'secretkey')

# Use flask-login for login management
login_manager = LoginManager()
login_manager.init_app(app)
# Unauthenticated requests to login protected pages cause a redirect to the
# login page
login_manager.login_view = "login"

app.debug = conf.get('ui', 'debug')


# FIXME move to a module
class IPAUser(object):
    userid = None

    def __init__(self, userid):
        self.userid = userid

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.userid


@login_manager.user_loader
def load_user(userid):
    return IPAUser(userid)


@app.route('/')
@not_logged_in_required
def root():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
@not_logged_in_required
def login():
    form = LoginForm()

    if form.validate_on_submit():
        login_user(IPAUser(form.username.data))
        flash('You have been logged in')
        return redirect(request.form.get('next') or url_for('account'))

    # If we have a URL to go back to after logging in, save that as a hidden
    # form field
    form.next.data = request.args.get('next')
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    # If we're logged in, log back out
    if current_user.is_authenticated():
        logout_user()
        flash('You have been logged out')

    # Either way, redirect to the front page
    return redirect(url_for('root'))


@app.route('/register', methods=['GET', 'POST'])
@not_logged_in_required
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        return redirect(url_for(''))

    return render_template('register.html', form=form)


@app.route('/recover')
@not_logged_in_required
def recover():
    form = RecoverForm()

    if form.validate_on_submit():
        return redirect(url_for(''))

    return render_template('recover.html', form=form)


@app.route('/account')
@login_required
def account():
    return render_template('account.html', id=current_user.get_id())


if __name__ == '__main__':
    app.run()
