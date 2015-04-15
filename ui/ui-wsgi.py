from os.path import abspath, dirname
import sys
sys.path.insert(0, dirname(abspath(__file__)))

from mypa_web import app as application
