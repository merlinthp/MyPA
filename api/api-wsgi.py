from ladon.server.wsgi import LadonWSGIApplication
from os.path import abspath, dirname

application = LadonWSGIApplication(
    ['mypa_rr_api'],
    [dirname(abspath(__file__))],
    catalog_name='MyPA service catalogue',
    catalog_desc='This is the API service catalogue for MyPA')
