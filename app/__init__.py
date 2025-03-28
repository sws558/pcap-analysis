# from email.mime import application
from .exts import *

from flask import Flask

app = Flask(__name__, instance_relative_config=True)
from app import views
app.config.from_object('config')

init_exts(app=app)