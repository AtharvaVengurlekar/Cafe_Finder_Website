from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config.from_object('config.Config')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20)) 
    location = db.Column(db.String(255)) 

class Cafe(db.Model):
    __bind_key__ = 'cafefinder' 
    __tablename__ = 'cafes'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    map_url = db.Column(db.String(255), nullable=False)
    img_url = db.Column(db.String(255), nullable=False)
    has_socket = db.Column(db.Boolean, default=False)
    has_toilet = db.Column(db.Boolean, default=False)
    has_wifi = db.Column(db.Boolean, default=False)
    can_take_calls = db.Column(db.Boolean, default=False)
    seats = db.Column(db.String(50), nullable=False)  
    coffee_prize = db.Column(db.String(50), nullable=False)  
    veg = db.Column(db.Boolean, nullable=False)  
    non_veg = db.Column(db.Boolean, nullable=False)  
    
class Owner(db.Model, UserMixin):
    __tablename__ = 'owner'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())    

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    if session.get('user_type') == 'owner':
        return Owner.query.get(int(user_id))
    return User.query.get(int(user_id))

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/owner_dashboard')
def owner_dashboard():
    return render_template('owner_dashboard.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        phone = request.form['phone']
        location = request.form['location']

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password, phone=phone, location=location)

        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            session['user_type'] = 'user'  
            flash('Login successful!', 'success')
            return redirect(url_for('cafe_filters'))  
        else:
            flash('Login Unsuccessful. Please check your email and password', 'danger')

    return render_template('login.html')

@app.route('/cafe_filters', methods=['GET', 'POST'])
@login_required
def cafe_filters():
    if request.method == 'POST':
        selected_filters = request.form.getlist('filters')
        query = Cafe.query

        if 'has_wifi' in selected_filters:
            query = query.filter_by(has_wifi=True)
        if 'has_socket' in selected_filters:
            query = query.filter_by(has_socket=True)
        if 'can_take_calls' in selected_filters:
            query = query.filter_by(can_take_calls=True)
        if 'has_toilet' in selected_filters:
            query = query.filter_by(has_toilet=True)

        cafes = query.all()
    else:
        cafes = Cafe.query.all()

    return render_template('cafe_filters.html', cafes=cafes)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out!', 'info')
    return redirect(url_for('dashboard'))

@app.route('/owner_register', methods=['GET', 'POST'])
def owner_register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        phone = request.form['phone']
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_owner = Owner(name=name, email=email, password=hashed_password, phone=phone)

        db.session.add(new_owner)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('owner_login'))

    return render_template('owner_register.html')

@app.route('/owner_login', methods=['GET', 'POST'])
def owner_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        owner = Owner.query.filter_by(email=email).first()

        if owner and bcrypt.check_password_hash(owner.password, password):
            login_user(owner)
            session['user_type'] = 'owner'  
            flash('Login successful!', 'success')
            return redirect(url_for('add_cafe'))
        else:
            flash('Login Unsuccessful. Please check your email and password', 'danger')

    return render_template('owner_login.html')

@app.route('/add_cafe', methods=['GET', 'POST'])
@login_required
def add_cafe():
    if request.method == 'POST':
        name = request.form['name']
        location = request.form['location']
        map_url = request.form['map_url']
        img_url = request.form['img_url']
        has_socket = 'has_socket' in request.form
        has_toilet = 'has_toilet' in request.form
        has_wifi = 'has_wifi' in request.form
        can_take_calls = 'can_take_calls' in request.form
        seats = request.form['seats']
        coffee_prize = request.form['coffee_prize']
        
        veg = request.form.get('veg') is not None
        non_veg = request.form.get('non_veg') is not None

        new_cafe = Cafe(
            name=name,
            location=location,
            map_url=map_url,
            img_url=img_url,
            has_socket=has_socket,
            has_toilet=has_toilet,
            has_wifi=has_wifi,
            can_take_calls=can_take_calls,
            seats=seats,
            coffee_prize=coffee_prize,
            veg=veg,
            non_veg=non_veg
        )
        db.session.add(new_cafe)
        db.session.commit()

        flash('Cafe added successfully!', 'success')
        return redirect(url_for('owner_dashboard'))

    return render_template('add_cafe.html')

@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
