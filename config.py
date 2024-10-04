#config.py from cafe finder website 

import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'your_secret_key')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'postgresql://your_username:your_password@localhost/flask_login')
    SQLALCHEMY_BINDS = {
        'cafefinder': os.getenv('CAFEFINDER_DB_URL', 'postgresql://your_username:your_password@localhost/CafeFinder')
    }
    SQLALCHEMY_TRACK_MODIFICATIONS = False