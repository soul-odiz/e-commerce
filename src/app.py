from datetime import datetime
from flask_migrate import Migrate
import paypalrestsdk
from flask import Flask, request, redirect, flash, session, jsonify, url_for, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS, cross_origin
from sqlalchemy.dialects.postgresql import JSON
import stripe
from flask_jwt_extended import (
    JWTManager,
    jwt_required,
    create_access_token,
    get_jwt_identity
)

app = Flask(__name__)

# Set your Stripe API keys
stripe.api_key = 'sk_test_51Nf0H6JMrP0vcBRKFh2h0Bd27UhR0btmqrr7E23Y5ow87XnIObgGawTb84imgqvu1JMy8JAmJ3PtP9cZQS4yGe5A00MxNufRbP'
app.secret_key = 'a_random_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies']
app.config['JWT_SECRET_KEY'] = 'jwt_secret_key'

paypalrestsdk.configure({
    "mode": "sandbox",
    "client_id": "AfrDmqiUpvM0wuljHbZ9pQFxFLOMuFtx02rW7oZ_Zlq5TcqXRkSmseCRyKh97dVEmNZ01FqADRveDl47",
    "client_secret": "EPMhvPif8avmxkjMePhK5R2UfOXcfxduxcv_lTPaTQnUcpZ9sh1RKfL64dzSb43WRyfoXsTIWd-ijwiD",
})

db = SQLAlchemy(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})



class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(100), nullable=False)
    options = db.Column(JSON, nullable=True)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    category = db.relationship('Category', backref=db.backref('items', lazy=True))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)


class Title(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    is_manager = db.Column(db.Boolean, default=False)
    items = db.relationship('Item', backref='user', lazy=True)


class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('cart_items', lazy=True))
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    item = db.relationship('Item', backref=db.backref('in_carts', lazy=True))
    quantity = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed = db.Column(db.Boolean, default=False)
    paid = db.Column(db.Boolean, default=False)


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    image = db.Column(db.String(100), nullable=False)


with app.app_context():
    db.create_all()

@app.route('/titles', methods=['GET', 'POST'])
def manage_titles():
    if request.method == 'POST':
        content = request.json.get('content')
        if not content:
            return jsonify({"success": False, "message": "Title content is required."}), 400

        # Check if a title already exists
        existing_title = Title.query.first()

        # If a title exists, update it. Otherwise, create a new one.
        if existing_title:
            existing_title.content = content
        else:
            title = Title(content=content)
            db.session.add(title)

        db.session.commit()
        return jsonify({"success": True, "message": "Title added/updated successfully."}), 201

    titles = Title.query.all()
    titles_data = [{'id': title.id, 'content': title.content} for title in titles]
    return jsonify(titles_data), 200


@app.route('/title', methods=['GET'])
def get_title():

    title = Title.query.first()

    if not title:
        return jsonify({"success": False, "message": "No title found."}), 404

    return jsonify({"success": True, "content": title.content}), 200


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.json.get('username')
        password = request.json.get('password')
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            access_token = create_access_token(identity=str(user.id))
            if user.is_manager:
                return jsonify({
                    "success": True,
                    "is_manager": True,
                    "token": access_token,
                    "loggedIn": True
                }), 200
            else:
                return jsonify({
                    "success": True,
                    "is_manager": False,
                    "token": access_token,
                    "loggedIn": True
                }), 200
        else:
            return jsonify({
                "success": False,
                "message": "Invalid username or password",
                "loggedIn": False
            }), 401

    return jsonify({
        "success": False,
        "message": "Invalid method",
        "loggedIn": False
    }), 405


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.json.get('username')
        email = request.json.get('email')
        password = request.json.get('password')
        first_name = request.json.get('first_name')
        last_name = request.json.get('last_name')
        is_manager = request.json.get('is_manager', False)
        hashed_password = generate_password_hash(password)
        user = User(
            username=username,
            email=email,
            password_hash=hashed_password,
            first_name=first_name,
            last_name=last_name,
            is_manager=is_manager
        )

        db.session.add(user)
        db.session.commit()

        return jsonify({"success": True, "loggedIn": True}), 201

    return jsonify({"success": False, "message": "Invalid method", "loggedIn": False}), 405


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"loggedIn": False}), 200


@app.route('/check_login', methods=['GET'])
def check_login():
    if 'user_id' in session:
        return jsonify({"loggedIn": True}), 200
    else:
        return jsonify({"loggedIn": False}), 200


@app.route('/items/<int:item_id>', methods=['PUT'])
@jwt_required()
def edit_item(item_id):
    user_id = get_jwt_identity()

    item = db.session.get(Item, item_id)

    if not item:
        return jsonify({"success": False, "message": "Item not found."}), 404

    user = db.session.get(User, user_id)
    if item.user_id != user_id and not user.is_manager:
        return jsonify({"success": False, "message": "Access denied."}), 403

    data = request.get_json()


    # Update item details based on provided data
    if 'name' in data:
        item.name = data['name']
    if 'description' in data:
        item.description = data['description']
    if 'price' in data:
        item.price = float(data['price'])
    if 'image' in data:
        item.image = data['image']
    if 'options' in data:
        item.options = data['options']
    if 'category_id' in data:
        item.category_id = data['category_id']

    try:
        db.session.commit()
        return jsonify({"success": True, "message": "Item updated successfully."}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/manager/dashboard')
@jwt_required()
def manager_dashboard():
    user_id = get_jwt_identity()
    user = db.session.get(User, user_id)
    if not user.is_manager:
        return jsonify({"success": False, "message": "Access denied."}), 403

    if user.is_manager:
        items = Item.query.filter_by(user_id=user.id).all()
    else:
        items = []

    items_data = [{'id': item.id, 'name': item.name, 'description': item.description,
                   'price': item.price, 'image': item.image} for item in items]
    return jsonify({"success": True, "items": items_data}), 200


@app.route('/create_item', methods=['POST'])
def create_item():
    if request.method == 'POST':
        data = request.get_json()
        name = data['name']
        description = data['description']
        price = float(data['price'])
        image = data['image']
        category_id = data['category']
        options = data.get('options', [])  # Get the options from the request data
        category = db.session.get(Category, category_id)
        item = Item(name=name, description=description, price=price, image=image, category=category, options=options)
        db.session.add(item)
        db.session.commit()
        return jsonify({"success": True, "item": item.id}), 201

    return jsonify({"success": False, "message": "Invalid method"}), 405



@app.route('/create_category', methods=['POST'])
def create_category():
    if request.method == 'POST':
        name = request.json.get('name')
        image = request.json.get('image')

        if not name:
            return jsonify({"success": False, "message": "Category name is required."}), 400

        category = Category(name=name, image=image)

        db.session.add(category)
        db.session.commit()

        return jsonify({"success": True}), 201

    return jsonify({"success": False, "message": "Invalid method"}), 405



@app.route('/add_to_cart', methods=['POST'])
@jwt_required()
def add_to_cart():
    user_id = get_jwt_identity()
    if request.method == 'POST':
        item_id = request.json.get('item_id')
        item = db.session.get(Item, item_id)

        if not item:
            return jsonify({"success": False, "error": "Item not found."}), 404

        cart_item = CartItem.query.filter_by(user_id=user_id, item_id=item_id).first()
        if cart_item:
            cart_item.quantity += 1
        else:
            cart_item = CartItem(user_id=user_id, item_id=item_id, quantity=1)
            db.session.add(cart_item)

        db.session.commit()

        return jsonify({"success": True}), 200

    return jsonify({"success": False, "message": "Invalid method"}), 405

@app.route('/remove_from_cart/<int:item_id>', methods=['DELETE'])
@jwt_required()
def remove_from_cart(item_id):
    user_id = get_jwt_identity()
    if request.method == 'DELETE':
        cart_item = CartItem.query.filter_by(user_id=user_id, item_id=item_id).first()

        if not cart_item:
            return jsonify({"success": False, "message": "Item not found in the cart."}), 404

        if cart_item.quantity > 1:
            cart_item.quantity -= 1
            db.session.commit()
        else:
            db.session.delete(cart_item)
            db.session.commit()

        return jsonify({"success": True}), 200

    return jsonify({"success": False, "message": "Invalid method"}), 405


@app.route('/items', methods=['GET'])
def get_items():
    try:
        items = [item for item in Item.query.all() if item.options]
        items_data = [{'id': item.id, 'name': item.name, 'description': item.description,
                       'price': item.price, 'image': item.image, 'options': item.options} for item in items]
        return jsonify(items_data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/categories/<int:category_id>/items', methods=['GET'])
def get_items_by_category(category_id):
    try:
        items = Item.query.filter_by(category_id=category_id).all()
        items_data = [{'id': item.id, 'name': item.name, 'description': item.description,
                       'price': item.price, 'image': item.image, 'options': item.options} for item in items]
        return jsonify(items_data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/items/<int:item_id>', methods=['DELETE'])
@jwt_required()
def delete_item(item_id):
    user_id = get_jwt_identity()
    item = db.session.get(Item, item_id)

    if not item:
        return jsonify({"success": False, "message": "Item not found."}), 404

    if item.user_id != user_id and not User.query.get(user_id).is_manager:
        return jsonify({"success": False, "message": "Access denied."}), 403

    try:
        db.session.delete(item)
        db.session.commit()
        return jsonify({"success": True}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/categories/<int:category_id>', methods=['DELETE'])
@jwt_required()
def delete_category(category_id):
    user_id = get_jwt_identity()
    category = db.session.get(Category, category_id)

    if not category:
        return jsonify({"success": False, "message": "Category not found."}), 404

    if not db.session.get(User, user_id).is_manager:
        return jsonify({"success": False, "message": "Access denied."}), 403

    try:
        db.session.delete(category)
        db.session.commit()
        return jsonify({"success": True}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/categories', methods=['GET'])
def get_categories():
    try:
        categories = Category.query.all()
        categories_data = [{'id': category.id, 'name': category.name, 'image': category.image} for category in categories]
        return jsonify(categories_data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/cart', methods=['GET', 'POST'])
@jwt_required()
def cart():
    user_id = get_jwt_identity()
    user = db.session.get(User, user_id)
    cart_items = [item for item in user.cart_items if not item.paid]
    total = sum([item.item.price * item.quantity for item in cart_items])

    if request.method == 'POST':
        return jsonify({"success": True, "message": "Payment successful! Your order has been placed."}), 200

    return jsonify({"success": True, "cart_items": cart_items, "total": total}), 200

@app.route('/process_payment', methods=['POST'])
@jwt_required()
def process_payment():
    user_id = get_jwt_identity()
    user = db.session.get(User, user_id)
    cart_items = CartItem.query.filter_by(user_id=user_id).all()
    total = sum(item.item.price * item.quantity for item in cart_items)

    try:
        payment_method = request.json.get('payment_method')

        if payment_method == 'paypal':
            payment = paypalrestsdk.Payment({
                "intent": "sale",
                "payer": {
                    "payment_method": "paypal"
                },
                "redirect_urls": {
                    "return_url": "http://localhost:5000/execute_payment",
                    "cancel_url": "http://localhost:5000/cancel_payment"
                },
                "transactions": [
                    {
                        "amount": {
                            "total": "{:.2f}".format(total),
                            "currency": "ILS"
                        },
                        "description": "Your purchase description here"
                    }
                ]
            })
            if payment.create():
                for link in payment.links:
                    if link.method == "REDIRECT":
                        return jsonify({"success": True, "redirect_url": link.href}), 200
            return jsonify({"success": False, "error": "Failed to create payment on PayPal"}), 500

        elif payment_method == 'stripe':
            payment_intent = stripe.PaymentIntent.create(
                amount=int(total * 100),
                currency='ils',
            )

            return jsonify({"success": True, "client_secret": payment_intent.client_secret}), 200

        else:
            return jsonify({"success": False, "error": "Invalid payment method"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/execute_payment', methods=['POST'])
def execute_payment():
    payment_method = request.json.get('payment_method')
    payment_id = request.json.get('payment_id')
    user_id = get_jwt_identity()
    cart_items = CartItem.query.filter_by(user_id=user_id).all()

    if payment_method == 'paypal':
        if not payment_id:
            return jsonify({"success": False, "error": "Payment ID not provided"}), 400

        payer_id = request.json.get('payer_id')
        if not payer_id:
            return jsonify({"success": False, "error": "Payer ID not provided"}), 400

        try:
            payment = paypalrestsdk.Payment.find(payment_id)
            if payment.execute({"payer_id": payer_id}): # or any other successful payment condition
                for cart_item in cart_items:
                    cart_item.paid = True
                    db.session.commit()
                # Payment successful, clear the cart and return success message
                # Clear the cart here (code to clear the cart)
                return jsonify({"success": True, "message": "Payment successful! Your order has been placed."}), 200
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    elif payment_method == 'stripe':
        try:
            payment_intent = stripe.PaymentIntent.retrieve(payment_id)
            payment_intent.confirm()

            return jsonify({"success": True, "message": "Payment successful! Your order has been placed."}), 200
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500


@app.route('/cancel_payment', methods=['GET'])
def cancel_payment():
    return jsonify({"success": False, "error": "Payment was canceled"}), 200

@app.route('/cart/create_paypal_order', methods=['POST'])
@jwt_required()
def create_paypal_order():
    user_id = get_jwt_identity()
    cart_items = CartItem.query.filter_by(user_id=user_id).all()
    total = sum(item.item.price * item.quantity for item in cart_items)

    payment = paypalrestsdk.Payment({
        "intent": "sale",
        "payer": {
            "payment_method": "paypal"
        },
        "redirect_urls": {
            "return_url": "http://localhost:5000/execute_payment",
            "cancel_url": "http://localhost:5000/cancel_payment"
        },
        "transactions": [{
            "amount": {
                "total": "{:.2f}".format(total),
                "currency": "ILS"
            },
            "description": "Your purchase description here",
            "item_list": {
                "items": [
                    {
                        "name": cart_item.item.name,
                        "description": cart_item.item.description,
                        "quantity": str(cart_item.quantity),
                        "price": "{:.2f}".format(cart_item.item.price),
                        "currency": "ILS"
                    } for cart_item in cart_items
                ]
            }
        }]
    })


    if payment.create():
        for link in payment.links:
            if link.method == "REDIRECT":
                return jsonify({"success": True, "redirect_url": link.href}), 200

    return jsonify({"success": False, "error": "Failed to create payment on PayPal"}), 500


@app.route('/cart/create_checkout_session', methods=['POST'])
@jwt_required()
def create_checkout_session():
    try:
        user_id = get_jwt_identity()
        cart_items = CartItem.query.filter_by(user_id=user_id).all()
        line_items = [{
            'price_data': {
                'currency': 'ils',
                'product_data': {
                    'name': item.item.name,
                    'images': [item.item.image],
                },
                'unit_amount': int(item.item.price * 100),
            },
            'quantity': item.quantity,
        } for item in cart_items]

        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=line_items,
            mode='payment',
            success_url='http://localhost:3000',
            cancel_url='http://localhost:3000',
        )

        return jsonify({"success": True, "session_id": checkout_session.id}), 200
    except Exception as e:
        print("Error in create_checkout_session:", str(e))
        return jsonify({"success": False, "error": str(e)}), 500




@app.route('/orders', methods=['GET'])
@jwt_required()
def orders_page():
    if not db.session.get(User, get_jwt_identity()).is_manager:
        return jsonify({"success": False, "message": "Access denied."}), 403

    cart_items = CartItem.query.all()
    items_data = []
    for cart_item in cart_items:
        item_data = {
            'cartItemId': cart_item.id,
            'name': cart_item.item.name,
            'description': cart_item.item.description,
            'price': cart_item.item.price,
            'image': cart_item.item.image,
            'quantity': cart_item.quantity,
            'user_name': cart_item.user.username,
            'created_at': cart_item.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'completed': cart_item.completed
        }
        items_data.append(item_data)

    return jsonify({"success": True, "cart_items": items_data}), 200


@app.route('/mark_order_completed', methods=['POST'])
@jwt_required()
def mark_order_completed():
    try:
        data = request.get_json()
        cart_item_ids = data.get('cart_item_ids', [])
        user_id = get_jwt_identity()

        for cart_item_id in cart_item_ids:
            cart_item = db.session.query(CartItem).filter(CartItem.id == cart_item_id).first()  # Use query and filter to get the cart item

            if cart_item:
                if cart_item.user_id == user_id or db.session.query(User).get(user_id).is_manager:
                    cart_item.completed = True
                else:
                    return jsonify({"error": "Access denied. You don't have permission to mark this order as completed."}), 403
            else:
                return jsonify({"error": f"Cart item with ID {cart_item_id} not found"}), 404

        db.session.commit()

        # Log successful completion
        print("Orders marked as completed successfully")

        return jsonify({"message": "Orders marked as completed successfully"}), 200
    except Exception as e:
        # Log any exceptions that occur
        print("Error:", str(e))
        return jsonify({"error": str(e)}), 500



if __name__ == '__main__':
    app.run(debug=True)