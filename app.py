from flask import Flask, render_template, jsonify, request, redirect, make_response
import requests
from pymongo import MongoClient
from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.background import BackgroundScheduler
import jwt
from bson.objectid import ObjectId
from flask_cors import CORS

app = Flask(__name__)




client = MongoClient('localhost', 27017)
db = client.boards
users_collection = db.users
tokens_collection = db.tokens
CORS(app, supports_credentials=True)

def decode_token():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None  # 유효하지 않은 토큰

    token = auth_header.split(" ")[1]  # "Bearer TOKEN"에서 TOKEN 추출
    print("check token !!!!!", token)
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # 토큰 검증 및 디코딩
        print("check id !!!!!", payload.get("user_id"))
        return payload.get("user_id")  # 토큰에서 userId 추출
    except jwt.ExpiredSignatureError:
        return None  # 토큰 만료
    except jwt.InvalidTokenError:
        return None  # 유효하지 않은 토큰


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/index.html', methods=['GET'])
def getMainPage():
    return render_template('index.html')

@app.route('/create-product.html', methods=['GET'])
def getCreateProduct():
    return render_template('create-product.html')

@app.route('/login.html')
def user_login():
    return render_template('login.html')

'''특정 게시물 페이지 '''
@app.route('/product-detail/<id>', methods=['GET'])
def product_detail(id):
    print('here', id)
    product = db.boards.find_one({"_id": ObjectId(id)})
    if product:
        return render_template('product-detail.html', product=product)
    else:
        return jsonify({"result": "fail", "message": "상품을 찾을 수 없습니다."}), 404

'''특정 상품 정보 조회'''
@app.route('/find_product/<id>', methods=["GET"])
def find_product(id):
        product_id = ObjectId(id)  # 유효한 ObjectId로 변환
        product = db.boards.find_one({"_id": product_id})

        product["_id"] = str(product["_id"])  # _id를 문자열로 변환하여 반환
        return jsonify({"result": "success", "product": product})


''' 모든 상품 게시글 조회'''
@app.route('/api/products', methods=['GET'])
def getAllProducts():
    result = list(db.boa