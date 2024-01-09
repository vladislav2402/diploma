# models/models.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class ScanResult(db.Model):
    __tablename__ = 'scan_result'
    id = db.Column(db.Integer, primary_key=True)
    folder = db.Column(db.String, nullable=False)
    scan_result = db.Column(db.JSON, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ScanResult {self.folder}>'
