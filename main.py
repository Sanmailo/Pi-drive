# # from fastapi import FastAPI, HTTPException
# from pydantic import BaseModel, EmailStr
# import requests

# app = FastAPI()

# class Payments(BaseModel):
#     email: EmailStr
#     amount: str

# class PaystackWebhookPayload(BaseModel):
#     event: str
#     data: dict

# def accept_payments(email: str, amount: str):
#     url = "https://api.paystack.co/transaction/initialize"
#     headers = {
#         "Authorization": f"Bearer YOUR-PAYSTACK-SECRET-KEY"
#     }
#     data = {
#         "email": email,
#         "amount": amount  # amount should be multiplied by 100 if currency is in GHS
#     }
#     try:
#         response = requests.post(url, headers=headers, data=data)
#         response.raise_for_status()
#         return response.json()["data"]["authorization_url"]
#     except requests.exceptions.HTTPError as e:
#         return None

# @app.post("/initialize-transaction")
# async def initialize_payment(payment_details: Payments):
#     payment_url = accept_payments(email=payment_details.email, amount=payment_details.amount)
#     if payment_url is None:
#         return HTTPException(status_code=400, detail="Invalid request")
#     return {"payment_url": payment_url}

# @app.post("/paystack-webhook")
# async def paystack_webhook(payload: PaystackWebhookPayload):
#     if payload.event == "charge.success":
#         payment_data = payload.data
#         # Do something with payment data
#         # Example: Save payment data to database, send email to customer, update order status, etc.
#         return {"message": "Payment successful"}
#     return {"message": "Payment failed"}                      


from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from pymongo import MongoClient
from passlib.context import CryptContext
from jose import JWTError, jwt
from typing import List, Optional
from bson import ObjectId
from dotenv import load_dotenv
import os
import uvicorn 
import requests
from datetime import datetime, timedelta

# Load environment variables from .env file
load_dotenv()

app = FastAPI()

# MongoDB connection
client = MongoClient("mongodb+srv://sanmi2009:oeVE5JKWBEjf9BlH@cluster0.n1cvn6z.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client["registration"]
users_collection = db["users"]
bookings_collection = db["bookings"]

# Secret key generation
SECRET_KEY = os.getenv("SECRET_KEY")
PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY")

# JWT configuration
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# HTTP Bearer security scheme
bearer_scheme = HTTPBearer()

# Password hashing and verification
pwd_cxt = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Pydantic models
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: str = None

class User(BaseModel):
    email: str = None
    fullName: str = None
    disabled: bool = None

class UserInDB(User):
    hashed_password: str

class SignUp(BaseModel):
    fullName: str
    email: EmailStr
    phoneNumber: str
    sex: str
    password: str
    confirmPassword: str

class SignIn(BaseModel):
    email: EmailStr
    password: str

class Booking(BaseModel):
    bookingfrom: str
    bookingto: str
    bookingprice: str
    bookingseatNumber: str
    bookingdate: str
    bookingtime: str

class PaystackPayment(BaseModel):
    email: EmailStr
    amount: int

# Utility functions
def verify_password(plain_password, hashed_password):
    return pwd_cxt.verify(plain_password, hashed_password)

def get_user(email: str):
    return users_collection.find_one({"email": email})

def authenticate_user(email: str, password: str):
    user = get_user(email)
    if not user or not verify_password(password, user["password"]):
        return False
    return user

async def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Routes
@app.post("/token", response_model=Token)
async def SignIn_for_access_token(email: str, password: str):
    user = authenticate_user(email, password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = await create_access_token(
        data={"sub": user["email"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=User)
async def read_users_me(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    token = credentials.credentials
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = get_user(token_data.email)
    if user is None:
        raise credentials_exception
    return user

@app.post("/SignUp")
async def Sign_Up_user(user: SignUp):
   if user.password != user.confirmPassword:
      raise HTTPException(status_code=400, detail="Passwords do not match")
   hashed_password = pwd_cxt.hash(user.password)
   user_data = user.dict()
   user_data["password"] = hashed_password
   del user_data["confirmPassword"]
   users_collection.insert_one(user_data)
   return {"message": "User SignUp successfully"}

@app.post("/SignIn")
async def Sign_In_user(form_data: SignIn):
    user = get_user(form_data.email)
    if not user or not pwd_cxt.verify(form_data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = await create_access_token(
        data={"sub": user["email"]}, expires_delta=access_token_expires
    )
    return {"message": "SignIn successfully", "accessToken": access_token}

@app.post("/SignOut")
async def signOut_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        # Invalidate the token
        return {"message": "SignOut successfully"}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/forget_password")
async def forget_password(email: str):
    user = users_collection.find_one({"email": email})
    if user is None:
        raise HTTPException(status_code=404, detail="email not found")
    # Send password reset email (implementation needed)
    return {"message": "password reset email sent successfully"}

@app.post("/booking")
async def booking_slot(booking: Booking, credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    booking_data = booking.dict()
    booking_data["user_id"] = email
    bookings_collection.insert_one(booking_data)
    return {"message": "Booking successful"}

@app.get("/booking")
async def get_bookings(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    bookings = bookings_collection.find({"user_id": email})
    return {"bookings": [booking for booking in bookings]}

# Paystack payment integration
@app.post("/paystack/pay")
async def paystack_payment(payment: PaystackPayment):
    url = "https://api.paystack.co/transaction/initialize"
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "email": payment.email,
        "amount": payment.amount * 100  # Paystack expects amount in kobo (1 NGN = 100 kobo)
    }
    response = requests.post(url, headers=headers, json=data)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())
    return response.json()

# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port=8000)

# if __name__ == "__main__":
#     port = int(os.environ.get("PORT", 8000))
#     uvicorn.run("main:app", host="0.0.0.0", port=8000)
