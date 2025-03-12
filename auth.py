import jwt
from functools import wraps
from flask import request, jsonify

def jwt_required(func):
    @wraps(func)
    def authenticated_function(*args, **kwargs):
        token = request.cookies.get("access_token")

        if not token:
            return jsonify({"error": "Authentication required"}), 401

        try:
            jwt.decode(token, key=JWT_SECRET, algorithms=["HS256"])

        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Access Token이 만료되었습니다."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Access Token 형식이 유효하지 않습니다."}), 401

        return func(*args, **kwargs)

    return authenticated_function