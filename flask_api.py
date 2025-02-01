import requests
import jwt
from jwt import InvalidTokenError
from jwt.algorithms import get_default_algorithms
from flask import Flask, request, jsonify
import boto3
from botocore.exceptions import ClientError
from flask_cors import CORS
from dotenv import load_dotenv
import os
import hmac
import hashlib
import base64
load_dotenv()

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

AWS_REGION = os.getenv("AWS_REGION")
USER_POOL_ID = os.getenv("USER_POOL_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
COGNITO_ISSUER = f"https://cognito-idp.{AWS_REGION}.amazonaws.com/{USER_POOL_ID}"
COGNITO_JWKS_URL = f"{COGNITO_ISSUER}/.well-known/jwks.json"

jwks_response = requests.get(COGNITO_JWKS_URL)
jwks = jwks_response.json()

@app.route('/getData', methods=['GET'])
def getAircrafts():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Authorization token is missing'}), 401

    if not validateToken(token):
        return jsonify({'error': 'Invalid token'}), 401

    # Rest of your logic here...
    dummy_data = [
        { "id": 1, "name": "Boeing 737", "manufacturer": "Boeing", "year": 1998 },
        { "id": 2, "name": "Airbus A320", "manufacturer": "Airbus", "year": 2000 },
        { "id": 3, "name": "Boeing 747", "manufacturer": "Boeing", "year": 1995 }
    ]

    return jsonify(dummy_data), 200

@app.route('/auth/signin', methods=['POST'])
def signin():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    client = boto3.client('cognito-idp', region_name=AWS_REGION)
    try:
        secret_hash = generate_secret_hash(CLIENT_ID, CLIENT_SECRET, email)
        response = client.initiate_auth(
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': email,
                'PASSWORD': password,
                'SECRET_HASH': secret_hash
            },
            ClientId=CLIENT_ID
        )
        return jsonify({"access_token": response['AuthenticationResult']['AccessToken']}), 200
    except ClientError as e:
        return jsonify({"error": str(e)}), 401
    
@app.route('/auth/signup', methods=['POST'])
def signup():
    data = request.json
    email = data.get('email')
    name = data.get('name')
    password = data.get('password')
    print(data)
    client = boto3.client('cognito-idp', region_name=AWS_REGION)
    try:
        secret_hash = generate_secret_hash(CLIENT_ID, CLIENT_SECRET, email)
        signup_response = client.sign_up(
            ClientId=CLIENT_ID,
            SecretHash=secret_hash,
            Username=email,
            Password=password,
            UserAttributes=[
                {'Name': 'email', 'Value': email},
                {'Name': 'name', 'Value': name}
            ]
        )
        print('signup_response', signup_response)

        # Authenticate the user after sign-up
        auth_response = client.initiate_auth(
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': email,
                'PASSWORD': password,
                'SECRET_HASH': secret_hash
            },
            ClientId=CLIENT_ID
        )
        print('auth_response', auth_response)
        return jsonify({"access_token": auth_response['AuthenticationResult']['AccessToken']}), 200
    except client.exceptions.UserNotConfirmedException:
        return jsonify({
            "message": "Check your email, we sent an OTP code."
        }), 403
    except ClientError as e:
        return jsonify({"error": str(e)}), 400

@app.route('/auth/confirm', methods=['POST'])
def confirm_signup():
    data = request.json
    email = data.get('email')
    code = data.get('code')
    client = boto3.client('cognito-idp', region_name=AWS_REGION)
    secret_hash = generate_secret_hash(CLIENT_ID, CLIENT_SECRET, email)
    try:
        client.confirm_sign_up(
            ClientId=CLIENT_ID,
            SecretHash=secret_hash,
            Username=email,
            ConfirmationCode=code
        )
        return jsonify({"message": "User confirmed successfully"}), 200
    except ClientError as e:
        return jsonify({"error": str(e)}), 400
    
@app.route('/auth/forgot-password', methods=['POST'])
def forgot_password():
    data = request.json
    email = data.get('email')
    client = boto3.client('cognito-idp', region_name=AWS_REGION)
    try:
        secret_hash = generate_secret_hash(CLIENT_ID, CLIENT_SECRET, email)
        client.forgot_password(
            ClientId=CLIENT_ID,
            SecretHash=secret_hash,
            Username=email
        )
        return jsonify({"message": "Verification code sent to your email" }), 200
    except ClientError as e:
        return jsonify({"error": str(e)}), 400
    except client.exceptions.UserNotFoundException:
        return jsonify({"error": "User does not exist"}), 404

@app.route('/auth/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    email = data.get('email')
    otp = data.get('code')
    new_password = data.get('password')
    client = boto3.client('cognito-idp', region_name=AWS_REGION)
    try:
        secret_hash = generate_secret_hash(CLIENT_ID, CLIENT_SECRET, email)
        client.confirm_forgot_password(
            ClientId=CLIENT_ID,
            SecretHash=secret_hash,
            Username=email,
            ConfirmationCode=otp,
            Password=new_password
        )
        return jsonify({"message": "Password reset successful"}), 200

    except ClientError as e:
        return jsonify({"error": str(e)}), 400
    
    except client.exceptions.CodeMismatchException:
      return jsonify({"error": "Invalid verification code"}), 400
    
    except client.exceptions.ExpiredCodeException:
      return jsonify({"error": "Verification code expired"}), 400
    
    except client.exceptions.UserNotFoundException:
      return jsonify({"error": "User not found"}), 404
    
# @app.route('/auth/validate-token', methods=['POST'])
# def validate_token():
#     token = request.headers.get('Authorization')
#     if not token:
#         return jsonify({'error': 'Authorization token is missing'}), 401

#     try:
#         if token.startswith('Bearer '):
#             token = token.split(' ')[1]

#         decoded_token = jwt.decode(
#             token,
#             key=get_public_key(jwt.get_unverified_header(token), jwks),
#             algorithms=['RS256'],
#             audience=CLIENT_ID if "aud" in jwt.decode(token, options={"verify_signature": False}) else None,
#             issuer=COGNITO_ISSUER
#         )

#         print("Token Decoded Successfully:", decoded_token)
#         return jsonify({'message': 'Token is valid', 'decoded_token': decoded_token}), 200

#     except InvalidTokenError as e:
#         print("Token Validation Failed:", e)
#         return jsonify({'error': 'Invalid token', 'details': str(e)}), 401

def validateToken(token):
    try:
        if token.startswith('Bearer '):
            token = token.split(' ')[1]

        decoded_token = jwt.decode(
            token,
            key=get_public_key(jwt.get_unverified_header(token), jwks),
            algorithms=['RS256'],
            audience=CLIENT_ID if "aud" in jwt.decode(token, options={"verify_signature": False}) else None,
            issuer=COGNITO_ISSUER
        )

        # print("Token Decoded Successfully:", decoded_token) # If needed the decoded token contains additional user information
        return True

    except InvalidTokenError as e:
        print("Token Validation Failed:", e)
        return False
    
def get_public_key(header, jwks):
    for key in jwks['keys']:
        if key['kid'] == header.get('kid'):
            rsa_key = get_default_algorithms()['RS256'].from_jwk(key)
            return rsa_key
    
    raise InvalidTokenError('Public key not found')

def generate_secret_hash(client_id, client_secret, username):
    message = username + client_id
    dig = hmac.new(client_secret.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).digest()
    return base64.b64encode(dig).decode()


if __name__ == '__main__':
    app.run(debug=True)

