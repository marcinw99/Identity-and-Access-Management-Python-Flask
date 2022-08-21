import json
from functools import wraps
from urllib.request import urlopen

from flask import request
from jose import jwt

AUTH0_DOMAIN = 'huffer.eu.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'drinks-service'

ERROR_CODES = {
    'noAuthorizationHeader': 'NO_AUTHORIZATION_HEADER',
    'invalidHeader': 'INVALID_HEADER',
    'invalidClaims': 'INVALID_CLAIMS',
    'unauthorized': 'UNAUTHORIZED',
    'tokenExpired': 'TOKEN_EXPIRED'
}


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


def get_token_auth_header():
    auth = request.headers.get('Authorization', None)
    if not auth:
        raise AuthError({
            'code': ERROR_CODES['noAuthorizationHeader'],
            'description': 'Authorization header expected'
        }, 401)

    parts = auth.split()

    if parts[0].lower() != 'bearer':
        raise AuthError({
            'code': ERROR_CODES['invalidHeader'],
            'description': 'Authorization header must start with "Bearer".'
        }, 401)

    elif parts[1] is None:
        raise AuthError({
            'code': ERROR_CODES['invalidHeader'],
            'description': 'Token not found.'
        }, 401)

    elif len(parts) > 2:
        raise AuthError({
            'code': ERROR_CODES['invalidHeader'],
            'description': 'Authorization header must be bearer token.'
        }, 401)

    token = parts[1]
    return token


def check_permissions(required_permission, payload):
    if required_permission is None:
        return True

    if 'permissions' not in payload:
        raise AuthError({
            'code': ERROR_CODES['invalidClaims'],
            'description': 'Permissions not included in the JWT.'
        }, 400)

    if required_permission not in payload['permissions']:
        raise AuthError({
            'code': ERROR_CODES['unauthorized'],
            'description': 'Permission not found.'
        }, 403)
    return True


def verify_decode_jwt(token):
    jwksUrl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')

    jwks = json.loads(jwksUrl.read())

    unverified_header = jwt.get_unverified_header(token)

    rsa_key = {}

    if 'kid' not in unverified_header:
        raise AuthError({
            'code': ERROR_CODES['invalidHeader'],
            'description': 'Authorization malformed, required key set is not '
                           'present. '
        }, 401)

    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer='https://' + AUTH0_DOMAIN + '/'
            )
            return payload

        except jwt.ExpiredSignatureError:
            raise AuthError({
                'code': ERROR_CODES['tokenExpired'],
                'description': 'Token expired.'
            }, 401)

        except jwt.JWTClaimsError:
            raise AuthError({
                'code': ERROR_CODES['invalidClaims'],
                'description': 'Incorrect claims. Please, check the audience '
                               'and the issuer. '
            }, 401)
        except Exception:
            raise AuthError({
                'code': ERROR_CODES['invalidHeader'],
                'description': 'Unable to parse authentication token.'
            }, 400)
    raise AuthError({
        'code': ERROR_CODES['invalidHeader'],
        'description': 'Unable to find the appropriate key.'
    }, 400)


def requires_auth(permission=None):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper

    return requires_auth_decorator
