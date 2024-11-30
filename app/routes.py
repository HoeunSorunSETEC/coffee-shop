from flask import Blueprint, jsonify, render_template, request, redirect, url_for, session


from werkzeug.security import check_password_hash, generate_password_hash
from app import db
from app.models import User, MenuItem, Order

main_blueprint = Blueprint('main', __name__)


@main_blueprint.route('/')
def login():
    if 'user_id' in session:
        return redirect(url_for('main.dashboard'))
    return render_template('login.html')


@main_blueprint.route('/login', methods=['GET', 'POST'])
def login_post():
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()

    # Correctly verify the password
    if user and check_password_hash(user.password, password):
        session['user_id'] = user.id
        return redirect(url_for('main.dashboard'))

    return 'Invalid Credentials'


@main_blueprint.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('main.login'))


@main_blueprint.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('main.login'))

    # Query all menu items from the database
    menu_items = MenuItem.query.all()

    # Group items by category
    menu = {}
    for item in menu_items:
        category = item.category  # Assume `category` is a field in your MenuItem model
        if category not in menu:
            menu[category] = []
        menu[category].append(item)

    return render_template('dashboard.html', menu=menu)

@main_blueprint.route('/menu')
def menu():
    menu_items = MenuItem.query.all()
    return jsonify([{'id': item.id, 'name': item.name, 'price': item.price} for item in menu_items])


@main_blueprint.route('/order', methods=['POST'])
def order():
    data = request.get_json()
    item_id = data.get('item_id')
    quantity = data.get('quantity')

    menu_item = MenuItem.query.get(item_id)
    if not menu_item:
        return jsonify({'error': 'Invalid item ID'}), 400

    total_price = menu_item.price * quantity
    order = Order(item_id=item_id, quantity=quantity, total_price=total_price)
    db.session.add(order)
    db.session.commit()

    return jsonify({'message': 'Order placed successfully', 'total_price': total_price})


@main_blueprint.route('/admin/create_user', methods=['GET', 'POST'])
def create_user():
    if 'user_id' not in session:
        return redirect(url_for('main.login_post'))

    admin_user = User.query.get(session['user_id'])
    if admin_user.role != 'admin':
        return 'Access Denied'

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'user')  # Default to 'user'

        if User.query.filter_by(username=username).first():
            return 'User already exists'

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        return 'User created successfully'

    return render_template('create_user.html')


@main_blueprint.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('main.login_post'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Verify current password
        if not check_password_hash(user.password, current_password):
            return 'Current password is incorrect'

        # Ensure new passwords match
        if new_password != confirm_password:
            return 'New passwords do not match'

        # Update password
        user.password = generate_password_hash(new_password)
        db.session.commit()

        return 'Password updated successfully'

    return render_template('change_password.html')