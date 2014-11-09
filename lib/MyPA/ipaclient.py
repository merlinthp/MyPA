import urllib
import httplib
from Cookie import SimpleCookie
import json
from time import time
from MyPA.utils import gen_randpass
from pprint import pprint


class IPAFormForbiddenError(Exception):
    def __init__(self, headers):
        self.headers = {}
        for header in headers:
            self.headers[header[0]] = header[1]


class IPAFormStatusError(Exception):
    pass


class IPALoginError(Exception):
    """
    An error during IPA session login.
    """
    pass


class IPAJSONError(Exception):
    """
    An error during an IPA JSON-RPC API call.
    """
    pass


class IPAChPassError(Exception):
    pass


class IPAPassPolicyError(Exception):
    pass


class ipaclient:
    """
    A class for calling various IPA methods, primarily using the JSON-RPC API
    """
    _server = None
    _user = None
    _password = None
    _session_id = None
    _session_ts = 0
    _session_timeout = 0

    def __init__(self, server, user, password, timeout=600):
        self._server = server
        self._user = user
        self._password = password
        self._session_timeout = timeout

    def _call_form_req(self, url, params):
        """
        Calls one of the IPA urlencoded form entry points
        Internal call.
        """
        conn = httplib.HTTPSConnection(self._server)

        headers = {
            "Content-type": "application/x-www-form-urlencoded",
            "Referer": "https://%s/ipa/ui/" % self._server
        }

        encparams = urllib.urlencode(params)

        conn.request("POST", url, encparams, headers)
        response = conn.getresponse()

        if response.status == 200:
            return response
        elif response.status == 401:
            raise IPAFormForbiddenError(response.getheaders())
        else:
            raise IPAFormStatusError("Called returned status %d"
                                     % response.status)

    def _new_session(self):
        """
        Start a new session with the IPA server by logging in and getting a
        cookie
        """

        params = {"user": self._user, "password": self._password}
        reqheader = []

        try:
            response = self._call_form_req("/ipa/session/login_password",
                                           params)

            # first make a note of when we got the session ID
            self._session_ts = time()

            c = SimpleCookie()
            c.load(response.getheader("set-cookie"))
            self._session_id = c["ipa_session"].value
        except IPAFormForbiddenError as e:
            if "x-ipa-rejection-reason" in e.headers:
                raise IPALoginError(e.headers["x-ipa-rejection-reason"])
            else:
                raise IPALoginError("Unknown error")

    def _call_json_rpc_req(self, params):
        """
        Low-level call to make a call to the JSON-RPC API.
        Not for public consumption.
        """

        conn = httplib.HTTPSConnection(self._server)

        headers = {
            "Content-type": "application/json",
            "Referer": "https://%s/ipa/ui/" % self._server,
            "Accept": "application/json",
            "Cookie": "ipa_session=%s" % self._session_id
        }

        conn.request("POST", "/ipa/session/json", params, headers)

        return conn.getresponse()

    def _call_json_rpc(self, method, params):
        """
        Call the IPA JSON-RPC API.
        """

        got_new_session = 0

        # First of all, check if the session will have timed out by now.
        # If it has, we need to start a new session.
        if time() > self._session_ts + self._session_timeout:
            try:
                self._new_session()
            except IPALoginError as e:
                raise IPAJSONError("Failed to start session: %s" % e)
            got_new_session = 1

        req_params = "{\"method\":\"%s\",\"params\":%s}" % (method,
                                                            json.dumps(params))

        response = self._call_json_rpc_req(req_params)

        # I'm sure there's a neater way of doing this bit of retry logic...

        if response.status == 401:
            # Not authorised.  Some problem with out session ID
            if got_new_session == 0:
                # We did't think the session was due to expire, but it did.
                # So start a new one.
                self._new_session()

                # Try again
                response = self._call_json_rpc_req(req_params)
                if response.status == 401:
                    # But we only just logged in...
                    raise IPAJSONError(
                        "Request failed after logging in. Check IPA logs.")
                elif response.status == 200:
                    return response.read()
                else:
                    raise IPAJSONError("JSON API returned code %d" %
                                       response.status)

            else:
                # But we only just logged in...
                raise IPAJSONError(
                    "Request failed after logging in. Check IPA logs.")
        elif response.status == 200:
            try:
                struct = json.loads(response.read())
                if "result" in struct:
                    return struct["result"]
                else:
                    raise IPAJSONError("JSON didn't include result data")
            except Exception as e:
                raise IPAJSONError("Failed to decode response body")
        else:
            raise IPAJSONError("JSON API returned code %d" % response.status)

    def user_info(self, username):
        """
        Fetch the info for an IPA user.  Returns the raw result data.
        """
        body = None
        try:
            body = self._call_json_rpc("user_show", [[username], {}])
        except IPAJSONError as e:
            # FIXME
            print "JSON call failed"

        if not body or "result" not in body:
            return None

        return body["result"]

    def user_exists(self, username):
        """
        Returns true if a user exists, false if not.
        """
        info = self.user_info(username)
        if info:
            return True
        else:
            return False

    def user_create(self, username, email, gn, sn, password):
        """
        Creates a new user in IPA with a minimum set of required attributes.

        FIXME: Need to validate the password before we create the user.
        """

        temppass = gen_randpass()
        body = None
        try:
            params = [[], {
                "uid": username,
                "mail": email,
                "givenname": gn,
                "sn": sn,
                "userpassword": temppass
            }]
            body = self._call_json_rpc("user_add", params)
        except IPAJSONError as e:
            # FIXME
            print "JSON call failed"

        if not body or "result" not in body:
            return False

        try:
            self.user_pass_change(username, temppass, password)
        except IPAPassPolicyError as e:
            # FIXME
            print "New password didn't meet policy requirements"
            return False

        return True

    def user_pass_change(self, username, oldpass, newpass):
        """
        Change the password of an IPA user given the old password.
        For admin-level password resets, see user_pass_reset()
        """

        params = {
            "user": username,
            "old_password": oldpass,
            "new_password": newpass
        }

        try:
            response = self._call_form_req("/ipa/session/change_password",
                                           params)
            if response.getheader("x-ipa-pwchange-result") == "policy-error":
                raise IPAPassPolicyError()
            elif response.getheader("x-ipa-pwchange-result") != "ok":
                raise IPAChPassError(
                    response.getheader("x-ipa-pwchange-result"))
        except IPAFormForbiddenError as e:
            raise IPAChPassError("")

        return True

    def user_pass_reset(self, username, password):
        """
        Reset a user's password to a specific value, using IPA admin rights.

        FIXME: There's a big issue with this: If the new password fails the
        IPA password quality checks, we're stuck in a situation where the
        password has been set to a random value.  Ideally we should ask IPA
        if the new password meets the quality checks _before_ doing the
        admin reset.  I don't think IPA has a way of validating a new
        password without trying to reset it.  Needs some thought.
        """

        temppass = gen_randpass()
        body = None
        try:
            params = [[username], {
                "userpassword": temppass
            }]
            body = self._call_json_rpc("user_mod", params)
        except IPAJSONError as e:
            print "JSON call failed"

        if not body or "result" not in body:
            return False

        try:
            self.user_pass_change(username, temppass, password)
        except IPAPassPolicyError as e:
            # FIXME
            print "New password didn't meet policy requirements"
            return False

        return True
