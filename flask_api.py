from flask import Flask, request, jsonify
import boto3
from botocore.exceptions import ClientError
import hmac
import hashlib
import base64

app = Flask(__name__)

# AWS Cognito configuration
AWS_REGION = "your-region-here"  # Replace with your AWS region
USER_POOL_ID = "your-user-pool-id"  # Replace with your Cognito User Pool ID
CLIENT_ID = "your-client-id"  # Replace with your Cognito App Client ID
CLIENT_SECRET = "your-client-secret"  # Replace with your Cognito App Client ID

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
    client = boto3.client('cognito-idp', region_name=AWS_REGION)
    try:
        secret_hash = generate_secret_hash(CLIENT_ID, CLIENT_SECRET, email)
        client.sign_up(
            ClientId=CLIENT_ID,
            SecretHash=secret_hash,
            Username=email,
            Password=password,
            UserAttributes=[
                {'Name': 'email', 'Value': email},
                {'Name': 'name', 'Value': name}
            ]
        )

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
        return jsonify({"access_token": auth_response['AuthenticationResult']['AccessToken']}), 200
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
        return jsonify({"message": "Verification code sent to your email"}), 200
    except ClientError as e:
        return jsonify({"error": str(e)}), 400
    except client.exceptions.UserNotFoundException:
        return jsonify({"error": "User does not exist"}), 404

@app.route('/auth/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    email = data.get('email')
    otp = data.get('otp')
    new_password = data.get('new_password')
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

    
def generate_secret_hash(client_id, client_secret, username):
    message = username + client_id
    dig = hmac.new(client_secret.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).digest()
    return base64.b64encode(dig).decode()


if __name__ == '__main__':
    app.run(debug=True)

