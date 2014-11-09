import re
import random
import string


def gen_randstring(length):
    return ''.join(random.choice(string.ascii_lowercase +
                                 string.ascii_uppercase +
                                 string.digits) for _ in range(length))


def gen_randtoken():
    return gen_randstring(40)


def gen_randpass():
    return gen_randstring(20)


# This isn't intended to be comprehensive
email_regex = re.compile(r'^.+@.+\.[^.]+$')


def validate_email(email):
    """
    A very basic email address validation function.
    """

    m = email_regex.match(email)

    return (m is not None)
