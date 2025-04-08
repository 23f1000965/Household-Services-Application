# 🏠 Household Services Platform
A multi-user web application that connects customers seeking home services with verified service professionals, managed through an admin dashboard. This platform supports service booking, real-time request tracking, professional verification, and user management.

# 📌 Project Overview
This project was developed as part of the Modern Application Development I course. The application provides a complete service management system for household needs like plumbing, AC servicing, and more.

# Three main roles are supported:
Admin: Superuser with full control over users, services, and requests.
Service Professional: Provides services after admin approval.
Customer: Books and manages service requests, submits reviews.

# ⚙️ Tech Stack
Component	Technology
Backend	Flask (Python)
Frontend	HTML + Jinja2 + Bootstrap
Database	SQLite
Authentication	Flask session management
ORM	SQLAlchemy
# 📁 Folder Structure
/household_app/
│
├── /templates/          # Jinja2 HTML templates
├── /static/             # CSS, JS, Bootstrap
├── /models/             # SQLAlchemy models
├── app.py               # Flask app (routes, views)
├── model.py             # Database models and config
├── requirements.txt     # List of Python dependencies
├── README.md            # Project documentation
└── household_services.db # SQLite database
# 🧑‍💼 User Roles & Features
# 👑 Admin
Login with predefined credentials (no registration).
View, approve or block service professionals.
View or block customers based on activity.
Add/update/delete services.
View all service requests.
Dashboard access to user and service management.

# 🧰 Service Professional
Register and await admin approval.
Login and view service requests assigned to their category.
Accept or reject requests.
Mark requests as completed.
View reviews left by customers.

# 🧑‍🔧 Customer
Register and login.
Browse or search services by location or name.
Create, edit, or close service requests.
Leave remarks/reviews after service completion.

# 🧾 Models Overview
# User (Customer)
id, name, email, password, blocked_status, ...
# Professional
id, name, service_type, experience, approved_status, ...
# Service
id, name, base_price, description, duration
# ServiceRequest
id, service_id, customer_id, professional_id, date_of_request, date_of_completion, status, remarks
# Admin
Hardcoded credentials (not stored in DB)

# 🔄 Application Flow
Customer or Professional registers and logs in.
Professional gets verified by Admin.
Customer searches and creates a request.
Professional accepts/rejects.
Upon completion, Customer closes the request and submits remarks.
Admin can monitor, update or block any user/service.

# 🔍 Search Functionality
Customers can filter services by:
Name
PIN Code
Location
# Admin can search:
Professionals to approve/block
Customers for review

🔐 Form validations (frontend + backend)

🔁 REST APIs (optional using flask_restful)


# 🚀 Getting Started
1. Clone the Repository
git clone https://github.com/yourusername/household-services-app.git
cd household-services-app
2. Install Requirements
pip install -r requirements.txt
3. Run the App
python app.py

# 👨‍💻 Contributors
🧑‍🎓 Your Name –Rohit kumar
 Student, IIT Madras

![App Screenshot](https://drive.google.com/uc?export=view&id=1Y7k_WahRVJ-gV7oVGPQsB_VI6h3NqDiz)









