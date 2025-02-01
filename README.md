
# Flask API with AWS Cognito Authentication

This project is a Python-based Flask API for user authentication using AWS Cognito. It implements the following endpoints:

1. **Sign In**: Authenticate a user with their email and password.
2. **Sign Up**: Register a new user.
3. **Forgot Password**: Initiate a password reset for a user.
4. **Reset Password**: Reset the user's password using a verification code.
5. **Get Data**: Dummy method to show how the token should be validated on any secure endpoint.

## Features
- Secure authentication using AWS Cognito.
- Support for **Sign In**, **Sign Up**, **Forgot Password**, and **Password Reset** flows.
- Integration with AWS SDK via `boto3`.

---

## Getting Started

### Prerequisites
- Python 3.8 or later installed.
- AWS account with a Cognito User Pool created.

### Installation
1. Clone the repository:
   ```bash
   git clone git@github.com:santiagommejia/flask-api-aws-cognito.git
   cd flask-api-aws-cognito
   ```
2. Create a virtual environment and activate it:
   ```bash
   python -m venv env
   source env/bin/activate  # On Windows: env\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## AWS Configuration

### **Step 1: Obtain Cognito Details**
You will need the following details from the AWS Cognito Console:
1. **AWS_REGION**: The region where your User Pool is located (e.g., `us-east-1`).
2. **USER_POOL_ID**: Your Cognito User Pool ID.
3. **CLIENT_ID**: Your Cognito App Client ID.
4. **CLIENT_SECRET**: The secret associated with the App Client (if enabled).

Replace these placeholders in the .env file:
```python
AWS_REGION = "your-region-here"  # e.g., us-east-1
USER_POOL_ID = "your-user-pool-id"
CLIENT_ID = "your-client-id"
CLIENT_SECRET = "your-client-secret"  # Only if your app client has a secret
```

---

### **Step 2: Enable Required Authentication Flows**
Ensure your Cognito App Client has the necessary authentication flows enabled:
1. Go to **Cognito** > **User Pools** > Your User Pool.
2. Under **App integration**, select your App Client.
3. Click **Show details** to expand the app client settings.
4. Click **Edit** and ensure the following flows are enabled:
   - `ALLOW_USER_PASSWORD_AUTH`
   - `ALLOW_REFRESH_TOKEN_AUTH`
5. Save the settings.

---

## API Endpoints

### **1. Sign In**
Authenticate a user.
- **Endpoint**: `/auth/signin`
- **Method**: `POST`
- **Request Body**:
  ```json
  {
    "email": "user@example.com",
    "password": "password123"
  }
  ```
- **Response**:
  ```json
  {
    "access_token": "your-access-token"
  }
  ```

---

### **2. Sign Up**
Register a new user.
- **Endpoint**: `/auth/signup`
- **Method**: `POST`
- **Request Body**:
  ```json
  {
    "email": "user@example.com",
    "name": "User Name",
    "password": "password123"
  }
  ```
- **Response**:
  ```json
  {
    "access_token": "your-access-token"
  }
  ```

---

### **3. Forgot Password**
Initiate a password reset.
- **Endpoint**: `/auth/forgot-password`
- **Method**: `POST`
- **Request Body**:
  ```json
  {
    "email": "user@example.com"
  }
  ```
- **Response**:
  ```json
  {
    "message": "Verification code sent to your email"
  }
  ```

---

### **4. Reset Password**
Reset a user’s password using the OTP.
- **Endpoint**: `/auth/reset-password`
- **Method**: `POST`
- **Request Body**:
  ```json
  {
    "email": "user@example.com",
    "otp": "123456",
    "new_password": "newPassword123"
  }
  ```
- **Response**:
  ```json
  {
    "message": "Password reset successful"
  }
  ```

---

### **5. Get Data**
Validate the token received in the Authorization header.
- **Endpoint**: `/getData`
- **Method**: `GET`
- **Headers**:
  ```
  Authorization: Bearer <your-token-here>
  ```
- **Response**:
  ```json
  {
    ... your response here ...
  }
  ```

---
## Deployment
To run the API locally:
1. Start the Flask server:
   ```bash
   python flask_api.py
   ```
2. The API will be available at `http://127.0.0.1:5000`.

---

## Notes
- Ensure AWS credentials are set up properly. Run:
  ```bash
  aws configure
  ```

---

