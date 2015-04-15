from flask.ext.wtf import Form, TextField, PasswordField, HiddenField

class LoginForm(Form):
    username = TextField()
    password = PasswordField()
    next = HiddenField()


class RegisterForm(Form):
    username = TextField()
    email = TextField()


class RecoverForm(Form):
    username = TextField()
