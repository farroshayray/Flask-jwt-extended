from flask import Flask, render_template, redirect, url_for, flash, abort, request, jsonify, make_response
from connectors.config import Config
from models.models import db, Users, Review
from auth import auth as auth_blueprint
from pages.reviews import reviews as reviews_blueprint
from functools import wraps
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, unset_jwt_cookies

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
jwt = JWTManager(app)

with app.app_context():
    db.create_all()

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        identity = get_jwt_identity()
        user = Users.query.filter_by(email=identity).first()
        if not user or user.role != 'Admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    if request.is_json:
        response = jsonify({"msg": "Token has expired"})
        unset_jwt_cookies(response)
        return response, 401
    else:
        flash("Your session has expired. Please log in again.", "warning")
        response = make_response(redirect(url_for('auth.login')))
        unset_jwt_cookies(response)
        return response
    
@jwt.unauthorized_loader
def missing_jwt_callback(error):
    if request.is_json:
        return jsonify({"msg": "unauthorized, please login first"}), 401
    else:
        return render_template('unauthorized.html'), 401

@app.errorhandler(403)
def forbidden_error_handler(error):
    if request.is_json:
        return jsonify({"message": "forbidden, please login as Admin"}), 403
    else:
        return render_template('forbidden.html'), 403

app.register_blueprint(auth_blueprint, url_prefix='/auth')
app.register_blueprint(reviews_blueprint, url_prefix='/reviews')

@app.route('/', methods=['GET'])
@jwt_required(optional=True)
def home():
    identity = get_jwt_identity()
    user = Users.query.filter_by(email=identity).first() if identity else None
    username = user.username if user else None
    logrole = user.role if user else None
    return render_template('home.html', username=username, logrole=logrole, reviews=Review.query.all())

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/users', methods=['GET'])
@jwt_required()
def users():
    identity = get_jwt_identity()
    user = Users.query.filter_by(email=identity).first()
    if not user:
        abort(401)
    
    if request.is_json:
        users = Users.query.all()
        return jsonify({'data': [{'email': u.email, 'username': u.username, 'role': u.role, 'id': u.id} for u in users]}), 200

    return render_template('users.html', logusername=user.username, logrole=user.role, users=Users.query.all())

@app.route('/users/delete/<int:user_id>', methods=['POST', 'DELETE'])
@jwt_required()
@admin_required
def delete_user(user_id):
    if request.method == 'DELETE':
        user = Users.query.get(user_id)
        if not user:
            if request.is_json:
                return jsonify({'message': "Data doesn't exist"}), 404
            flash("User does not exist", "danger")
            return redirect(url_for('users'))

        db.session.delete(user)
        db.session.commit()
        
        if request.is_json:
            return jsonify({'message': 'User deleted successfully!'}), 200
        
        flash('User deleted successfully!', 'success')
        return redirect(url_for('users'))
    if request.method == 'POST':
        user = Users.query.get(user_id)
        if not user:
            if request.is_json:
                return jsonify({'message': "Data doesn't exist"}), 404
            flash("User does not exist", "danger")
            return redirect(url_for('users'))

        db.session.delete(user)
        db.session.commit()
        
        if request.is_json:
            return jsonify({'message': 'User deleted successfully!'}), 200
        
        flash('User deleted successfully!', 'success')
        return redirect(url_for('users'))
    
if __name__ == "__main__":
    app.run(debug=True)
