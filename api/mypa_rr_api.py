from ladon.ladonizer import ladonize
from ladon.types.ladontype import LadonType

from ConfigParser import ConfigParser
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import jinja2
from sqlite3 import dbapi2 as sqlite3
from sqlite3 import IntegrityError
from MyPA.ipaclient import ipaclient
from MyPA.utils import gen_randtoken, validate_email

conf_file = "/etc/MyPA/api.ini"
conf = ConfigParser()
conf.read(conf_file)

jenv = jinja2.Environment(loader=jinja2.FileSystemLoader(
                          conf.get('email', 'template_dir')))
db = sqlite3.connect(conf.get('db', 'path'))
db.row_factory = sqlite3.Row
ipaclient = ipaclient(conf.get('ipa', 'host'),
                      conf.get('ipa', 'user'),
                      conf.get('ipa', 'pass'))


def ipa_user_info(username):
    return ipaclient.user_info(username)


def ipa_user_exists(username):
    return ipaclient.user_exists(username)


def ipa_user_create(username, email, gn, sn, password):
    return ipaclient.user_create(username, email, gn, sn, password)


def ipa_user_reset_pwd(username, password):
    return ipaclient.user_pass_reset(username, password)


def pendingdb_add(username, email, etype, replace=True):
    authkey = gen_randtoken()

    repsql = ""
    if replace:
        repsql = "OR REPLACE "
    sql = "INSERT %sINTO pending_req (type, username, email, authenticator, " \
          "expiry) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)" % repsql

    # if we're not replacing, and there's a key clash, sqlite raises an
    # exception
    try:
        with db:
            cur = db.execute(sql, (etype, username, email, authkey))
    except IntegrityError:
        return None

    if cur.rowcount == 0:
        return False

    return authkey


def pendingdb_del(username, etype):
    with db:
        db.execute('DELETE FROM pending_req WHERE username = ? AND type = ?',
               (username, etype))
    return True


def pendingdb_validate(username, token, etype):
    with db:
        cur = db.execute('SELECT email FROM pending_req WHERE username = ? '
                         'AND authenticator = ? AND type = ?',
                         (username, token, etype))
        row = cur.fetchone()
        if row:
            return row[0]
        else:
            return None


def pendingdb_add_reg(username, email):
    """
    Create a new registration request and authorization token for the specified
    username/email pair.  If an existing request exists, the request will fail.
    Returns the token, or None in the event of failure.

    Wrapper around pendingdb_add.
    """
    return pendingdb_add(username, email, 'register', replace=False)


def pendingdb_del_reg(username):
    """
    Delete a pending registration from the database.  Returns True if a
    registration request was deleted, or False if not.

    Wrapper around pendingdb_del.
    """
    return pendingdb_del(username, 'register')


def pendingdb_validate_reg(username, token):
    """
    Check if a username/token pair matches a pending registration request.
    If it does, return the email address from the request, or None if it
    doesn't.

    Wrapper around pendingdb_validate.
    """
    return pendingdb_validate(username, token, 'register')


def pendingdb_add_rec(username, email):
    """
    Create a new recovery request and authorization token for the specified
    username/email pair.  If an existing request exists, it will be
    overwritten.  Returns the token.

    Wrapper around pendingdb_add.
    """
    return pendingdb_add(username, email, 'recover')


def pendingdb_del_rec(username):
    """
    Delete any pending recovery request that may exist for the specified
    username.  Returns True if a recovery request was deleted, or False if not.

    Wrapper around pendingdb_del.
    """
    return pendingdb_del(username, 'recover')


def pendingdb_validate_rec(username, token):
    """
    Check if a username/token pair matches a pending recovery request.
    If it does, return the email address from the request.

    Wrapper around pendingdb_validate.
    """
    return pendingdb_validate(username, token, 'recover')


def send_email(email, subject, parts, renderargs):
    # always make a multipart alternative email. Not really seeing a need
    # for this to be configurable
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = conf.get('email', 'mail_from')
    msg['To'] = email

    for (part, ptype) in parts:
        templ = jenv.get_template(part)
        text = templ.render(rargs=renderargs)

        mpart = MIMEText(text, ptype)

        msg.attach(mpart)

    if conf.getboolean('email', 'send'):
        # send the mail
        s = smtplib.SMTP(conf.get('email', 'mailserver'))
        s.sendmail(conf.get('email', 'mail_from'), [email], msg.as_string())
        s.quit()
    else:
        print msg.as_string()


class RRAPIReturn(LadonType):
    """
    Return type for MyPA_RR_API methods.
    """

    status = unicode
    message = unicode

    def ok(self, message):
        """
        Sets the return status to ok, and sets a message.
        Returns the object itself for convenience.
        """
        self.status = "ok"
        self.message = message
        return self

    def error(self, message):
        """
        Sets the return status to error, and sets a message.
        Returns the object itself for convenience.
        """
        self.status = "error"
        self.message = message
        return self


class MyPA_RR_API(object):
    """
    The MyPA Register and Recovery API.

    Registering new users and resetting passwords (recovery) requires
    elevated priviliges in IPA.  This API forms a discrete private WSGI
    application which only performs these operations.
    """

    @ladonize(unicode, unicode, rtype=RRAPIReturn)
    def createRegisterRequest(self, username, email):
        """
        Create a request to register a new user, and send the confirmation
        email.

        @param username: Username for the new user.
        @param email: Email address to send the confirmation mail to.
        @rtype: ok or error, and a message
        """

        retobj = RRAPIReturn()

        if username == "":
            return retobj.error("Invalid username")

        if not validate_email(email):
            return retobj.error("Invalid email address")

        if ipa_user_exists(username):
            return retobj.error("Username is not available")

        authkey = pendingdb_add_reg(username, email)
        if not authkey:
            return retobj.error("Username is not available")

        parts = (
                ("register.txt", "plain"),
                ("register.html", "html")
            )
        rargs = {"user": username, "key": authkey}
        send_email(email, conf.get('email', 'register_subject'), parts, rargs)

        return retobj.ok("Registration requested")

    @ladonize(unicode, unicode, rtype=RRAPIReturn)
    def validateRegisterRequest(self, username, token):
        """
        Validate a registration request token.

        @param username: Username for the new user.
        @param token: Validation token string.
        @rtype: ok or error, and a message
        """

        retobj = RRAPIReturn()

        if username == "":
            return retobj.error("Invalid username")

        if token == "":
            return retobj.error("Invalid token")

        if not pendingdb_validate_reg(username, token):
            return retobj.error("Invalid token")

        return retobj.ok("Valid token")

    @ladonize(unicode, unicode, unicode, unicode, unicode, rtype=RRAPIReturn)
    def completeRegisterRequest(self, username, token, gn, sn, password):
        """
        Complete a registration request and register the user with IPA.

        @param username: Username for the new user.
        @param token: Validation token string.
        @param gn: New user given name.
        @param sn: New user surname.
        @param password: Password for new user account.
        @rtype: ok or error, and a message
        """

        retobj = RRAPIReturn()

        if username == "":
            return retobj.error("Invalid username")

        if token == "":
            return retobj.error("Invalid token")

        if gn == "":
            return retobj.error("Given name is invalid")

        if sn == "":
            return retobj.error("Surname is invalid")

        # More complex password validation rules?  IPA will do it.
        if password == "":
            return retobj.error("Password is invalid")

        email = pendingdb_validate_reg(username, token)
        if not email:
            return retobj.error("Invalid token")

        if ipa_user_exists(username):
            pendingdb_del_reg(username)
            return retobj.error("Username is not available")

        # Now try and create the user in IPA
        if not ipa_user_create(username, email, gn, sn, password):
            return retobj.error("User creation failed")

        pendingdb_del_reg(username)

        # Send the user an email to confirm the registration
        parts = (
                ("registerconf.txt", "plain"),
                ("registerconf.html", "html")
            )
        rargs = {"user": username}
        send_email(email, conf.get('email', 'register_comp_subject'), parts,
                   rargs)

        return retobj.ok("User created")

    @ladonize(unicode, unicode, rtype=RRAPIReturn)
    def cancelRegisterRequest(self, username, token):
        """
        Cancel a pending registration request.

        @param username: Username of .
        @param token: Validation token string.
        @rtype: ok or error, and a message
        """

        retobj = RRAPIReturn()

        if username == "":
            return retobj.error("Invalid username")

        if token == "":
            return retobj.error("Invalid token")

        if not pendingdb_validate_reg(username, token):
            return retobj.error("Unknown request")

        pendingdb_del_reg(username)

        return retobj.ok("Request cancelled")

    @ladonize(unicode, rtype=RRAPIReturn)
    def createRecoveryRequest(self, username):
        """
        Create a request to recover a user account, and send the confirmation
        email.

        @param username: Username of the account to recover.
        @rtype: ok or error, and a message
        """

        retobj = RRAPIReturn()

        if username == "":
            return retobj.error("Invalid user")

        # FIXME should we have a way to exempt some accounts from recovery?
        # I'm not sure we should let someone try and recover Jim's account,
        # for example (if only to protect people from the evil within)

        # Two thoughts: either we have a configured user blacklist (something
        # to forget to update when new "important" users come along, or we
        # could blacklist based on group membership.

        userinfo = ipa_user_info(username)
        if not userinfo:
            return retobj.error("Unknown user")

        email = userinfo['mail'][0]

        authkey = pendingdb_add_rec(username, email)
        if not authkey:
            return retobj.error("Unable to request recovery")

        parts = (
                ("recover.txt", "plain"),
                ("recover.html", "html")
            )
        rargs = {"user": username, "key": authkey}
        send_email(email, conf.get('email', 'recover_subject'), parts, rargs)

        return retobj.ok("Recovery requested")

    @ladonize(unicode, unicode, rtype=RRAPIReturn)
    def validateRecoveryRequest(self, username, token):
        """
        Validate a recovery request.

        @param username: Username of the account to recover.
        @param token: Validation token string.
        @rtype: ok or error, and a message
        """
        retobj = RRAPIReturn()

        if username == "":
            return retobj.error("Invalid username")

        if token == "":
            return retobj.error("Invalid token")

        if not pendingdb_validate_req(username, token):
            return retobj.error("Invalid token")

        return retobj.ok("Valid token")

    @ladonize(unicode, unicode, unicode, rtype=RRAPIReturn)
    def completeRecoveryRequest(self, username, token, password):
        """
        Complete a recovery request, and reset the user's password in IPA.

        @param username: Username of the account to recover.
        @param token: Validation token string.
        @param password: New password to reset the account to.
        @rtype: ok or error, and a message
        """

        retobj = RRAPIReturn()

        if username == "":
            return retobj.error("Invalid username")

        if token == "":
            return retobj.error("Invalid token")

        if password == "":
            return retobj.error("Invalid password")

        email = pendingdb_validate_rec(username, token)
        if not email:
            return retobj.error("Invalid token")

        # Check that the account exists in IPA.  It might have been deleted
        # since the recovery request was created.
        if not ipa_user_exists(username):
            # Delete the recovery request, it's not use now.
            pendingdb_del_rec(username)
            return retobj.error("User does not exist")

        if not ipa_user_reset_pwd(username, password):
            return retobj.error("Recovery failed")

        pendingdb_del_rec(username)

        # Send the user a mail confirming the recovery.
        parts = (
                ("recoverconf.txt", "plain"),
                ("recoverconf.html", "html")
            )
        rargs = {"user": username}
        send_email(email, conf.get('email', 'recover_comp_subject'), parts,
                   rargs)

        return retobj.ok("Account recovered")

    @ladonize(unicode, unicode, rtype=RRAPIReturn)
    def cancelRecoveryRequest(self, username, token):
        """
        Cancel a pending recovery request.

        @param usernmae: Username of the account to recover.
        @param token: Validation token string.
        @rtype: ok or error, and a message
        """

        retobj = RRAPIReturn()

        if username == "":
            return retobj.error("Invalid username")

        if token == "":
            return retobj.error("Invalid token")

        if pendingdb_validate_rec(username, token):
            return retobj.error("Unknown request")

        pendingdb_del_rec(username)

        return retobj.ok("Request cancelled")
