MyPA is a self-service front end for FreeIPA.

MyPA allows users to request and recover their own user accounts without intervention from an IPA server admin.

IMPORTANT NOTE: Because users can request their own account creation, it is CRITICAL that these newly-created accounts should not have any permissions to log into secure systems.  That means that access to those systems should be controlled with HBAC rules (or similar) that do not permit new users to authenticate (e.g. the IPA default "allow_all" HBAC rule should be disabled or deleted).

MyPA is licenced under the GPLv2.

Requirements
============

MyPA is tested against FreeIPA 3.3 and Python 2.7.

Architecture
============

MyPA consists of two main elements, a front end web interface, and a back end XMLRPC API.  Both the web interface and the API talk to an IPA instance, using IPA's JSON-RPC API.

The XMLRPC API is used to perform a handful of privileged operations in IPA, using an IPA admin user.  It is not exposed to end users, only to the server running the front end web UI.

Some Useful Notes on IPA
========================

JSON-RPC API
------------

The IPA JSON-RPC API is used by the IPA web interface.  The web UI use logs in (using either form post with username and password auth, or kerberos via http negotiate auth) and is given a session cookie.  This cookie is then used to authenticate requests to the JSON-RPC API.

Logging in:

POST to /ipa/session/login_password with content-type application/x-www-form-urlencoded, and URL-encoded body containing the parameters user and password.  On successful auth, the IPA server will return a cookie called ipa_session which can be used to authenticate the JSON requests.  On unsuccessful auth, IPA will give a reason in the x-ipa-rejection-reason header.

Calling the API:

POST to /ipa/session/json with content-type application/json, accept application/json, and the ipa_session cookie from the login_password call.  The POST body should be a JSON document similar to the following (spacing optional):

{
  "method": "user_show",
  "params": [
    ["user1"],
    {}
  ]
}

similarly:

{
  "method": "user_add",
  "params": [
    [],
    {
      "uid": "user2",
      "mail": "user2@example.com",
      "givenname": "User",
      "sn": "Two",
      "userpassword": "letmein"
    }
  ]
}

Resetting user passwords
------------------------

There are two ways to change a password in IPA.  Either the user can change their own password (in which case they need to provide their current password for authentication), or an admin user can reset the users password instead (without needing the current password).

The issue with the latter is that IPA enforces a (sensible) policy whereby if the password of an account is set by any user other than the account owner, the password is immediately set to expired.  This forces the user to reset their password on next login.  This is a pretty sensible, as means that long-term, an admin doesn't know another users password.

That causes MyPA problems, however.  MyPA needs to create new user accounts with a provided password, and reset existing user passwords to a provided value, using an admin user account.  To do this, MyPA uses both the above methods in turn.

When creating a new user, or resetting a password, MyPA sets the user password to a temporary (random) value using the the JSON-RPC API, then changes the password to the final value, using the IPA web UI change password POST method.

The one wrinkle with this two-step approach is password quality validation.  IPA's password policy includes password quality (or strength) settings around minimum length, complexity, etc.  When an admin changes a user password, this validation is not done.  When a user changes their own password it is.  This means that it is possible for the second stage of the password reset to fail, and leave the user account in limbo.  Ideally we need to pre-validate the new user password against the IPA password policy.  Not sure how to do that without reimplmenting the validation logic, though...

Process Flows
=============

This section documents some of the basic process flows in MyPA.  Various elements of error checking and handling may be omitted.

Registering a new user
----------------------

- The end user fills in the new user form on the web UI (which is not authenticated), providing a desired username and email address.
- The web UI dispatches a "request new user" call to the XMLRPC API.
- The XMLRPC API checks that the username is available to register, generates a registration authentication token, records these in a local database, and sends an email to the email address, containing a URL to a web UI page to confirm the registration, including the token.
- The user receives the email, and clicks on the link.
- The web UI sends a request to the API to validate the request (using the token).
- The API checks the token against its local database, and sends an ok response back to the web UI.
- The web UI asks the user for some more information to complete the registration (name, password).
- The web UI passes a "register new user" call the API, including the new collected information, and the token.
- The API once again validates the token, then calls the IPA user_add API, creating the user with a temporary password.
- The API calls the IPA change_password form method to reset the temporary password to the requested password.

Recovering an existing user
---------------------------

- The end user fills in a "reset my password" form on the web UI
- The web UI dispatches a "recover user request" call to the XMLRPC API
- The XMLRPC API checks that the username exists in IPA, generates a recovery authentication token, records this in a local database, and sends an email to the user's registered email address, containing a URL to the a web UI page to confirm the recovery, including the token.
- The user receives the email, and clicks on the link.
- The web UI sends a request to the API to validate the request (using the token).
- The API checks the token against its local database, and sends and ok response back to the web UI.
- The web UI asks the user for a new password for the user account.
- The web UI passes a "confirm user recovery" call to the API, including the token and the new password.
- The API again validates the token, then calls the IPA user_mod API to reset the password to a random temporary password.
- The API calls the IPA change_password form method to reset the temporary password to the requested password.
