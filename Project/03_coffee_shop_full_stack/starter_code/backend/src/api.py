import json

from flask import Flask, jsonify, request, abort
from flask_cors import CORS

from .auth.auth import requires_auth, AuthError
from .database.models import setup_db, Drink, db_drop_and_create_all

app = Flask(__name__)
setup_db(app)
CORS(app)

db_drop_and_create_all()


def short_format_drinks(drinks):
    return [drink.short() for drink in drinks]


def long_format_drinks(drinks):
    return [drink.long() for drink in drinks]


# ROUTES


@app.route('/drinks', methods=['GET'])
def get_drinks():
    drinks = Drink.query.all()

    return jsonify({
        'success': True,
        'drinks': short_format_drinks(drinks)
    })


@app.route('/drinks-detail', methods=['GET'])
@requires_auth(permission='get:drinks-detail')
def get_drinks_details(token):
    drinks = Drink.query.all()

    return jsonify({
        'success': True,
        'drinks': long_format_drinks(drinks)
    })


@app.route('/drinks', methods=['POST'])
@requires_auth(permission='post:drinks')
def create_drink(token):
    body = request.get_json()

    req_title = body.get('title', None)
    req_recipe = body.get('recipe', None)

    if None in [req_title, req_recipe]:
        abort(400)

    new_drink = Drink(title=req_title, recipe=json.dumps(req_recipe))

    new_drink.insert()

    return jsonify({
        'success': True,
        'drinks': long_format_drinks([new_drink])
    })


@app.route('/drinks/<int:drink_id>', methods=['PATCH'])
@requires_auth(permission='patch:drinks')
def update_drink(token, drink_id):
    body = request.get_json()

    req_title = body.get('title', None)
    req_recipe = body.get('recipe', None)

    if req_title is None and req_recipe is None:
        abort(400)

    updated_drink = Drink.query.filter(Drink.id == drink_id).one_or_none()

    if updated_drink is None:
        abort(404)

    updated_drink.title = req_title
    updated_drink.recipe = json.dumps(req_recipe)

    updated_drink.update()

    return jsonify({
        'success': True,
        'drinks': long_format_drinks([updated_drink])
    })


@app.route('/drinks/<int:drink_id>', methods=['DELETE'])
@requires_auth(permission='delete:drinks')
def delete_drink(token, drink_id):
    drink = Drink.query.filter(Drink.id == drink_id).one_or_none()

    if drink is None:
        abort(404)

    drink.delete()

    return jsonify({
        'success': True,
        'delete': drink_id
    })


# Error Handling


@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        "success": False,
        "error": 400,
        "message": "bad request"
    }), 400


@app.errorhandler(401)
def unauthenticated(error):
    return jsonify({
        "success": False,
        "error": 401,
        "message": "user unauthenticated"
    }), 401


@app.errorhandler(403)
def unauthorized(error):
    return jsonify({
        "success": False,
        "error": 403,
        "message": "user unauthorized"
    }), 403


@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": 404,
        "message": "resource not found"
    }), 404


@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
        "success": False,
        "error": 422,
        "message": "unprocessable"
    }), 422


@app.errorhandler(AuthError)
def auth_error(e):
    return jsonify({
        "success": False,
        "error": e.status_code,
        "message": e.error
    }), e.status_code
