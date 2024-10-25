from flask import abort, request, render_template, flash, redirect, url_for, jsonify
from functools import wraps
from flask_jwt_extended import jwt_required, get_jwt_identity
from models.models import db, Review, Users
from . import reviews

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        identity = get_jwt_identity()
        user = Users.query.filter_by(email=identity).first()
        if not user or user.role != 'Admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@reviews.route('/', methods=['GET', 'POST'])
@jwt_required()
@admin_required
def review():
    identity = get_jwt_identity()
    user = Users.query.filter_by(email=identity).first()
    username = user.username if user else None
    role = user.role if user else None

    if request.method == 'POST':
        try:
            if request.is_json:
                data = request.get_json()
                email = data.get('email', user.email).strip()
                description = data.get('description', '').strip()
                rating = int(data.get('rating', '0'))
            else:
                email = user.email
                description = request.form['description'].strip()
                rating = int(request.form['rating'])

            if not description:
                raise ValueError("Description cannot be empty")
            if not (1 <= rating <= 5):
                raise ValueError("Rating must be between 1 and 5.")

            new_review = Review(description=description, email=email, rating=rating)
            db.session.add(new_review)
            db.session.commit()

            if request.is_json:
                return jsonify({
                    'data': {
                        'email': email,
                        'description': description,
                        'rating': rating
                    },
                    'message': 'Review added successfully!'
                }), 201

            flash('Review added successfully!', 'success')
            return redirect(url_for('reviews.review'))

        except ValueError as ve:  # for input validation errors
            db.session.rollback()
            if request.is_json:
                return jsonify({'error': str(ve)}), 400
            flash(str(ve), 'danger')

        except Exception as e:  # for general errors
            db.session.rollback()
            if request.is_json:
                return jsonify({'error': 'An error occurred. Please try again.'}), 500
            flash('An error occurred. Please try again.', 'danger')
            return redirect(url_for('reviews.review'))

    if request.method == 'GET':
        reviews = Review.query.all()
        if request.is_json:
            return jsonify({
                'data': [{
                    'review_id': review.review_id,
                    'email': review.email,
                    'description': review.description,
                    'rating': review.rating
                } for review in reviews]
            })
        return render_template('reviews.html', username=username, role=role, reviews=reviews)


@reviews.route('/delete/<int:review_id>', methods=['POST', 'DELETE'])
@jwt_required()
@admin_required
def delete_review(review_id):
    if request.method == 'DELETE':
        review = Review.query.get(review_id)

        if not review:
            if request.is_json:
                return jsonify({'message': "Data doesn't exist"}), 404
            flash("Data doesn't exist", 'danger')
            return redirect(request.referrer or url_for('reviews.review'))

        db.session.delete(review)
        db.session.commit()

        if request.is_json:
            return jsonify({'message': 'Review deleted successfully!'}), 200

        flash('Review deleted successfully!', 'success')
        return redirect(request.referrer or url_for('reviews.review'))
    if request.method == 'POST':
        review = Review.query.get(review_id)

        if not review:
            if request.is_json:
                return jsonify({'message': "Data doesn't exist"}), 404
            flash("Data doesn't exist", 'danger')
            return redirect(request.referrer or url_for('reviews.review'))

        db.session.delete(review)
        db.session.commit()

        if request.is_json:
            return jsonify({'message': 'Review deleted successfully!'}), 200

        flash('Review deleted successfully!', 'success')
        return redirect(request.referrer or url_for('reviews.review'))

@reviews.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    identity = get_jwt_identity()
    user = Users.query.filter_by(email=identity).first()
    
    username = user.username if user else None
    email = user.email if user else None
    role = user.role if user else None

    return render_template('dashboard.html', username=username, email=email, role=role)
