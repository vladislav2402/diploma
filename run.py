import os
from flask import Flask
from controllers.routes import register_routes
from models.models import db



def create_app():
    app = Flask(__name__)
    register_routes(app)
    return app

app = create_app()

#-------------------------------------------
app.config['UPLOAD_FOLDER'] = os.getcwd()
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://username:password@db/database_name'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#-------------------------------------------

db.init_app(app)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
