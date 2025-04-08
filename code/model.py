from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

from datetime import datetime


class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='admin')


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(255), nullable = False)
    pincode = db.Column(db.Integer, nullable = False)
    contact = db.Column(db.Integer, nullable = False)
    role = db.Column(db.String(20), nullable=False, default='customer') 
    status = db.Column(db.String(20), nullable=False, default='active')
    service_requests = db.relationship('ServiceRequest', backref='customer', lazy=True)

class Professional(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    service_provided = db.Column(db.String(100), nullable=False)
    pincode = db.Column(db.Integer, nullable = False)
    contact = db.Column(db.Integer, nullable = False)
    Experience = db.Column(db.Integer, nullable = False)
    serviceType = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='professional') 
    status = db.Column(db.String(20), nullable=False, default='available')  
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)  
    service_requests = db.relationship('ServiceRequest', backref='professional', lazy=True)
    
class Service(db.Model):    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    time_required = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='active')
    professionals = db.relationship('Professional', backref='service', lazy=True)
    service_requests = db.relationship('ServiceRequest', backref='service', lazy=True)

class ServiceRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    professional_id = db.Column(db.Integer, db.ForeignKey('professional.id'), nullable=True)
    date_of_request = db.Column(db.DateTime, default=lambda: datetime.utcnow().replace(second=0, microsecond=0))
    status = db.Column(db.String(20), nullable=False)  # requested, assigned, closed
    rating = db.Column(db.Integer, nullable=True)
    review = db.Column(db.String(255), nullable=True)




