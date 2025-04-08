from flask import Flask, render_template, redirect, url_for, request, session,flash
from werkzeug.security import generate_password_hash, check_password_hash
from model import db,User,Professional,ServiceRequest,Service,Admin
from datetime import datetime
app = Flask(__name__)


# Setting up the SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///household_services.db'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db.init_app(app)
app.app_context().push()
db.create_all()

# admin credential exists
def create_admin_credential():
    admin = Admin.query.filter_by(username="admin").first()
    if not admin:
        admin = Admin(username="admin", password=generate_password_hash("1234"), role="admin")
        db.session.add(admin)
        db.session.commit()

create_admin_credential()

# User login route
@app.route('/', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        professional = Professional.query.filter_by(username=username).first()

        admin = Admin.query.filter_by(username=username).first()
        if user:
            if user.status == 'blocked':
                flash('You have been blocked', 'danger')
                return render_template('login.html') 
            if user and check_password_hash(user.password, password):
                session['user_id'] = user.id
                session['role'] = user.role
                session['username'] = user.username

                if user.role == 'customer':
                    return redirect(url_for('customer_dashboard'))
            
        
        elif professional:
            if professional.status == 'blocked':
                flash('You have been blocked', 'danger')
                return render_template('login.html')
            if professional.status == 'pending':
                flash('Your request is pending', 'danger')
                return render_template('login.html')
            if professional.status == 'disapproved':
                flash('Your request is rejected apply again ', 'danger')
                return render_template('login.html')

            elif professional and check_password_hash(professional.password, password):
                session['user_id'] = professional.id
                session['role'] = professional.role
                session['username'] = professional.username
                session['full_name'] = professional.full_name


                if professional.role == 'professional':
                    return redirect(url_for('professional_dashboard'))
            
        elif admin and check_password_hash(admin.password, password):
            session['user_id'] = admin.id
            session['role'] = admin.role
            session['username'] = admin.username

            if admin.role == 'admin':
                return redirect(url_for('admin_dashboard'))

        else:
            flash('Invalid credentials, please try again', 'danger')

    return render_template('login.html')

# Admin login route
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == "admin" and password == "1234":
            admin = Admin.query.filter_by(username=username).first()
            if admin and check_password_hash(admin.password, password):
                session['user_id'] = admin.id
                session['role'] = admin.role
                session['username'] = admin.username
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Admin user not found, please try again'),
        else:
            flash('Invalid credentials, please try again', 'danger')

    return render_template('login.html')    


# User registration route
@app.route('/user', methods=['GET', 'POST'])
def user():

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        address = request.form.get('address')
        pincode = request.form.get('pincode')
        contact = request.form.get('contact')

        if not username or not password or not address or not pincode or not contact:
            flash('please fill the mandotary field')
            return render_template('user.html')
        

        exists_user = User.query.filter_by(username = username).first()
        if exists_user:
            flash('please select another username, this username is taken')
            return render_template('user.html')
    
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, address=address, pincode=pincode, contact=contact)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return render_template('login.html')
    return render_template('user.html')

#professional registration route
@app.route('/professional', methods=['GET', 'POST'])
def professional():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        full_name = request.form.get('full_name')
        service_provided = request.form.get('service_provided')
        pincode = request.form.get('pincode')
        contact = request.form.get('contact')
        experience = request.form.get('experience')
        serviceType = request.form.get('serviceType') 
        service = Service.query.filter_by(name=serviceType).first()

        if not username or not password or not full_name or not service_provided or not pincode or not contact or not experience or not serviceType :
            flash('please fill the mandotary field')
            return render_template('professional.html')
        
        exists_user = Professional.query.filter_by(username = username).first()
        if exists_user:
            flash('please select another username, this username is taken')
            return render_template('professional.html')
        status = 'pending'
        hashed_password = generate_password_hash(password)
        new_user = Professional(username=username, password=hashed_password, full_name=full_name, service_provided=service_provided, pincode=pincode, contact=contact, Experience=experience, serviceType=serviceType  , role='professional', status=status, service_id=service.id)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! wait for admin approval.', 'success')

        return render_template('login.html')
    service_types = Service.query.with_entities(Service.name).distinct().all()
    return render_template('professional.html', service_types=service_types)
    
############ Admin Dashboard##############
@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'role' in session and session['role'] == 'admin':
        users = Admin.query.all()
        services = Service.query.all()
        professionals = Professional.query.all()
        customers = User.query.all()
        service_requests = ServiceRequest.query.filter(ServiceRequest.status.in_(['requested', 'rejected', 'accepted', 'closed'])).all()
        pending_professionals = Professional.query.filter_by(status='pending').all()
        active_professionals = Professional.query.filter(Professional.status.in_(['approved', 'blocked'])).all()
        search_results = []
        search_option = None
        
        show_modal = False
        if request.method == 'POST':
            search_option = request.form['search_option']
            search_query = request.form['search_query']
            
            if search_option == 'professional':
                search_results = Professional.query.filter(Professional.full_name.contains(search_query)).all()
            elif search_option == 'user':
                search_results = User.query.filter(User.username.contains(search_query)).all()
            elif search_option == 'service_requests':
                search_results = ServiceRequest.query.filter_by(status='requested').all()
            elif search_option == 'accepted_requests':
                search_results = ServiceRequest.query.filter_by(status='accepted').all()
            elif search_option == 'closed_requests':
                search_results = ServiceRequest.query.filter_by(status='closed').all()
            elif search_option == 'rejected_requests':
                search_results = ServiceRequest.query.filter_by(status='rejected').all()
            elif search_option == 'services':
                search_results = Service.query.filter(Service.name.contains(search_query)).all()

            show_modal = True
        return render_template('admin_dashboard.html', users=users, services=services, professionals=professionals, customers=customers, pending_professionals=pending_professionals, active_professionals=active_professionals, service_requests=service_requests, search_results=search_results, search_option=search_option, show_modal=show_modal)
    return redirect(url_for('login'))



#approve professional
@app.route('/admin/approve_professional/<int:id>', methods=['POST'])
def approve_professional(id):
    professional = Professional.query.get(id)
    if 'role' in session and session['role'] == 'admin':
        professional.status = 'approved'
        db.session.commit()
        return redirect(url_for('admin_dashboard'))  
    return redirect(url_for('login'))

#disapprove professional
@app.route('/admin/disapprove_professional/<int:id>', methods=['POST'])
def disapprove_professional(id):
    professional = Professional.query.get(id)
    if 'role' in session and session['role'] == 'admin':
        professional.status = 'disapproved'
        db.session.commit()
        return redirect(url_for('admin_dashboard'))  
    return redirect(url_for('login'))

# View for Pending Professional Requests
@app.route('/admin/view_requests')
def view_requests():
    if 'role' in session and session['role'] == 'admin':
        # Fetch all professionals whose status is 'pending'
        professionals = Professional.query.filter_by(status='pending').all()
        return render_template('admin_dashboard.html', professionals=professionals)
    return redirect(url_for('login'))

# Block or Unblock the professional
@app.route('/admin/toggle_professional_status/<int:id>', methods=['POST'])
def toggle_professional_status(id):
    professional = Professional.query.get(id)
    if 'role' in session and session['role'] == 'admin':
        if professional.status == 'approved':
            professional.status = 'blocked'
        else:
            professional.status = 'approved'
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))

#Delete professional for (Admin only)
@app.route('/admin/delete_professional/<int:id>', methods=['POST','delete'])
def delete_professional(id):
    professional = Professional.query.get(id)
    if 'role' in session and session['role'] == 'admin':
        db.session.delete(professional)
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))

# Create service for (Admin only)
@app.route('/admin/create_service', methods=['GET', 'POST'])
def create_service():
    if 'role' in session and session['role'] == 'admin':
        if request.method == 'POST':
            service_name = request.form['name']
            description = request.form['description']
            price = request.form['price']
            time_required = request.form['time_required']
            new_service = Service(name=service_name, description=description, price=price, time_required=time_required)
            db.session.add(new_service)
            db.session.commit()
            return redirect(url_for('admin_dashboard'))
        return render_template('service_create.html')
    return redirect(url_for('login'))

# Edit service for (Admin only)
@app.route('/admin/edit_service/<int:id>', methods=['GET', 'POST'])
def edit_service(id):
    if 'role' in session and session['role'] == 'admin':
        service = Service.query.get(id)
        if request.method == 'POST':
            service.name = request.form['name']
            service.description = request.form['description']
            service.price = request.form['price']
            service.time_required = request.form['time_required']
            db.session.commit()
            return redirect(url_for('admin_dashboard'))
        return render_template('service_edit.html', service=service)
    return redirect(url_for('login'))

# Toggle service status for (Admin only)
@app.route('/admin/toggle_service_status/<int:id>', methods=['POST'])
def toggle_service_status(id):
    service = Service.query.get(id)
    if not service:
        
        return redirect(url_for('admin_dashboard'))
    
    if 'role' in session and session['role'] == 'admin':
        if service.status == 'active':
            service.status = 'inactive'
        else:
            service.status = 'active'
        db.session.commit()
        
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))

# Show service types for professionals to select
@app.route('/professional/select_service', methods=['GET', 'POST'])
def select_service():
    if 'role' in session and session['role'] == 'professional':
        if request.method == 'POST':
            selected_service_type = request.form['service_type']
            professional_id = session['user_id']
            professional = Professional.query.get(professional_id)
            professional.serviceType = selected_service_type
            db.session.commit()
            
            return redirect(url_for('professional_dashboard'))
        service_types = Service.query.with_entities(Service.name).distinct().all()
        return render_template('select_service_type.html', service_types=service_types)
    return redirect(url_for('login'))

#show user customer for admin only
@app.route('/admin/view_customers')
def view_customers():
    if 'role' in session and session['role'] == 'admin':
        customers = User.query.all()
        return render_template('admin_dashboard.html', customers=customers)
    return redirect(url_for('login'))

#block or unblock customer for admin only
@app.route('/admin/toggle_customer_status/<int:id>', methods=['POST'])
def toggle_customer_status(id):
    customer = User.query.get(id)
    if 'role' in session and session['role'] == 'admin':
        if customer.status == 'approved':
            customer.status = 'blocked'
        else:
            customer.status = 'approved'
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))

#delete customer for admin only
@app.route('/admin/delete_customer/<int:id>', methods=['POST','delete'])
def delete_customer(id):
    customer = User.query.get(id)
    if 'role' in session and session['role'] == 'admin':
        db.session.delete(customer)
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))


####### Customer Dashboard ########
@app.template_filter('exists_request')
def exists_request (service_id, professional_id, service_requests_with_professionals):
    for item in service_requests_with_professionals:
        if item['service_request'].service_id == service_id and item['service_request'].professional_id == professional_id and item['service_request'].status in ['requested', 'accepted']:
            return True
    return False
#customer dashboard
@app.route('/customer', methods=['GET', 'POST'])
def customer_dashboard():
    if 'role' in session and session['role'] == 'customer':
        customer_id = session['user_id']
        service_requests = ServiceRequest.query.filter_by(customer_id=customer_id).all()
        services = Service.query.all()
        customer = User.query.get(customer_id)
        search_results = []
        search_option = None
        show_modal = False
        
        if request.method == 'POST':
            search_option = request.form['search_option']
            search_query = request.form['search_query']

            if search_option == 'services':
                search_results = Service.query.filter(Service.name.contains(search_query)).all()
            elif search_option == 'professional_fullname':
                search_results = Professional.query.filter(Professional.full_name.contains(search_query)).all()
            elif search_option == 'pincode':
                search_results = Professional.query.filter(Professional.pincode.contains(search_query)).all()
            elif search_option == 'address':
                search_results = Professional.query.filter(Professional.service_provided.contains(search_query)).all()
            elif search_option == 'experience':
                search_results = Professional.query.filter(Professional.Experience.contains(search_query)).all()
            else:
                search_results = []

            show_modal = True

        # Fetch professionals for each service
        services_with_professionals = []
        for service in services:
            professionals = Professional.query.filter_by(service_id=service.id).all()
            services_with_professionals.append({
                'service': service,
                'professionals': professionals
            })
        
        # Fetch professional data for each service request
        service_requests_with_professionals = []
        for service_request in service_requests:
            professional = db.session.get(Professional, service_request.professional_id)
            service_requests_with_professionals.append({
                'service_request': service_request,
                'professional': professional
            })
        
        return render_template('customer_dashboard.html', service_requests_with_professionals=service_requests_with_professionals, services_with_professionals=services_with_professionals, search_results=search_results, search_option=search_option, show_modal=show_modal, customer=customer)
    return redirect(url_for('login'))

#view profile
@app.route('/customer/customer_profile', methods=['GET'])
def view_customer_profile():
    if 'role' in session and session['role'] == 'customer':
        user_id = session['user_id']
        customer = User.query.get(user_id)
        return render_template('customer/view_customer_profile.html', customer=customer)
    return redirect(url_for('login'))
#edit profile
@app.route('/customer/edit_customer_profile', methods=['POST'])
def edit_customer_profile():
    if 'role' in session and session['role'] == 'customer':
        customer_id = session['user_id']
        customer = User.query.get(customer_id)
        
        customer.username = request.form['username']
        customer.address = request.form['address']
        customer.contact = request.form['contact']
        customer.pincode = request.form['pincode']
        db.session.commit()

        session['username'] = customer.username
        
        return redirect(url_for('customer_dashboard'))
    return redirect(url_for('login'))
# Requested service by customer
@app.route('/customer/request_service', methods=['POST'])
def request_service():
    if 'role' in session and session['role'] == 'customer':
        service_id = request.form['service_id']
        professional_id = request.form['professional_id']
        customer_id = session['user_id']
        new_request = ServiceRequest(service_id=service_id, customer_id=customer_id, professional_id=professional_id, status='requested')
        db.session.add(new_request)
        db.session.commit()
        return redirect(url_for('customer_dashboard'))
    return redirect(url_for('login'))

# review service by customer
@app.route('/customer/review_service/<int:id>', methods=['POST'])
def review_service(id):
    if 'role' in session and session['role'] == 'customer':
        service_request = ServiceRequest.query.get(id)
        service_request.review = request.form['review']
        service_request.rating = request.form['rating']
        db.session.commit()
        
        return redirect(url_for('customer_dashboard'))
    return redirect(url_for('login'))

#edit a service requests
@app.route('/customer/edit_service_request/<int:id>', methods=['POST'])
def edit_service_request(id):
    if 'role' in session and session['role'] == 'customer':
        service_request = ServiceRequest.query.get(id)
        if service_request and service_request.customer_id == session['user_id']:
            date_of_request_str = request.form['date_of_request']
            date_of_request = datetime.strptime(date_of_request_str, '%Y-%m-%dT%H:%M')
            service_request.date_of_request = date_of_request
            db.session.commit()
        return redirect(url_for('customer_dashboard'))
    return redirect(url_for('login'))

#delete service requests
@app.route('/customer/delete_service/<int:id>', methods=['POST','delete'])
def delete_service_request(id):
    if 'role' in session and session['role'] == 'customer':
        service_request = ServiceRequest.query.get(id)
        if service_request:
            db.session.delete(service_request)
            db.session.commit()
        return redirect(url_for('customer_dashboard'))
    return redirect(url_for('login'))


########Professional Dashboard##########
@app.route('/professional_dashboard', methods=['GET', 'POST'])
def professional_dashboard():
    if 'role' in session and session['role'] == 'professional':
        professional_id = session['user_id']
        professional = Professional.query.get(professional_id)
        service_requests = ServiceRequest.query.filter_by(professional_id=professional_id).all()
        
        # Categorize service requests based on their status
        requested_requests = []
        accepted_requests = []
        closed_requests = []
        rejected_requests = []
        
        for service_request in service_requests:
            customer = db.session.get(User, service_request.customer_id)
            request_with_customer = {
                'service_request': service_request,
                'customer': customer
            }
            if service_request.status == 'requested':
                requested_requests.append(request_with_customer)
            elif service_request.status == 'accepted':
                accepted_requests.append(request_with_customer)
            elif service_request.status == 'closed':
                closed_requests.append(request_with_customer)
            elif service_request.status == 'rejected':
                rejected_requests.append(request_with_customer)
        
        search_results = []
        search_option = None
        show_modal = False
        
        if request.method == 'POST':
            search_option = request.form['search_option']
            search_query = request.form['search_query']

            if search_option == 'customer_name':
                search_results = User.query.join(ServiceRequest, User.id == ServiceRequest.customer_id) \
                                           .filter(ServiceRequest.professional_id == professional_id) \
                                           .filter(ServiceRequest.status.in_(['requested', 'accepted', 'closed', 'rejected'])) \
                                           .filter(User.username.contains(search_query)).all()
            elif search_option == 'pincode':
                search_results = User.query.join(ServiceRequest, User.id == ServiceRequest.customer_id) \
                                           .filter(ServiceRequest.professional_id == professional_id) \
                                           .filter(ServiceRequest.status.in_(['requested', 'accepted', 'closed', 'rejected'])) \
                                           .filter(User.pincode.contains(search_query)).all()
            elif search_option == 'contact':
                search_results = User.query.join(ServiceRequest, User.id == ServiceRequest.customer_id) \
                                           .filter(ServiceRequest.professional_id == professional_id) \
                                           .filter(ServiceRequest.status.in_(['requested', 'accepted', 'closed', 'rejected'])) \
                                           .filter(User.contact.contains(search_query)).all()
            elif search_option == 'address':
                search_results = User.query.join(ServiceRequest, User.id == ServiceRequest.customer_id) \
                                           .filter(ServiceRequest.professional_id == professional_id) \
                                           .filter(ServiceRequest.status.in_(['requested', 'accepted', 'closed', 'rejected'])) \
                                           .filter(User.address.contains(search_query)).all()
            else:
                search_results = []

            show_modal = True 
        
        return render_template('professional_dashboard.html', 
                               professional=professional,
                               requested_requests=requested_requests, 
                               accepted_requests=accepted_requests, 
                               closed_requests=closed_requests, 
                               rejected_requests=rejected_requests,
                               search_results=search_results,
                               search_option=search_option,
                               show_modal=show_modal)
    return redirect(url_for('login'))
#view professional profile
@app.route('/professional/profile', methods=['GET'])
def view_profile():
    if 'role' in session and session['role'] == 'professional':
        professional_id = session['user_id']
        professional = Professional.query.get(professional_id)
        return render_template('professional/view_profile.html', professional=professional)
    return redirect(url_for('login'))
#edit professional profile
@app.route('/professional/edit_profile', methods=['POST'])
def edit_profile():
    if 'role' in session and session['role'] == 'professional':
        professional_id = session['user_id']
        professional = Professional.query.get(professional_id)
        
        professional.full_name = request.form['full_name']
        professional.pincode = request.form['pincode']
        professional.contact = request.form['contact']
        professional.service_provided = request.form['service_provided']
        
        db.session.commit()

        session['full_name'] = professional.full_name
        
        return redirect(url_for('professional_dashboard'))
    return redirect(url_for('login'))
#accept service request by professional
@app.route('/professional_dashboard/accept_request/<int:id>', methods=['POST'])
def accept_request(id):
    if 'role' in session and session['role'] == 'professional':
        service_request = ServiceRequest.query.get(id)
        if service_request and service_request.professional_id == session['user_id']:
            
            service_request.status = 'accepted'
            db.session.commit()
            
        return redirect(url_for('professional_dashboard'))
    return redirect(url_for('login'))
#reject service request by professional
@app.route('/professional_dashboard/reject_request/<int:id>', methods=['POST'])
def reject_request(id):
    if 'role' in session and session['role'] == 'professional':
        service_request = ServiceRequest.query.get(id)
        if service_request and service_request.professional_id == session['user_id']:
            service_request.status = 'rejected'
            db.session.commit()
        return redirect(url_for('professional_dashboard'))
    return redirect(url_for('login'))
#close service request by professional
@app.route('/professional_dashboard/close_request/<int:id>', methods=['POST'])
def professional_close_request(id):
    if 'role' in session and session['role'] == 'professional':
        service_request = ServiceRequest.query.get(id)
        if service_request and service_request.professional_id == session['user_id']:
            
            service_request.status = 'closed'
            db.session.commit()
        return redirect(url_for('professional_dashboard'))
    return redirect(url_for('login'))
#####logout   Route    ########
@app.route('/logout')
def logout():
    session.pop("username")
    flash('You have been logged out',category="success")
    return redirect(url_for('login'))

# Initialize database and run app
if __name__ == "__main__":
    app.run(debug=True)
