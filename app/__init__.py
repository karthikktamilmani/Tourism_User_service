from flask import Flask
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)

app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY"),
    AWS_ACCESS_KEY_ID=os.environ.get("AWS_ACCESS_KEY_ID"),
    AWS_SECRET_ACCESS_KEY=os.environ.get("AWS_SECRET_ACCESS_KEY"),
    AWS_SESSION_TOKEN=os.environ.get("AWS_SESSION_TOKEN")
    #SECRET_KEY=b'_5#y2L"F4Q8z\n\xec]/'\
)

from app import routes

