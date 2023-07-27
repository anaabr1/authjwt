from fastapi import FastAPI, HTTPException, Depends, Form
from fastapi.security import OAuth2PasswordBearer
import jwt
import secrets
import datetime

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


fake_users_db = {
    "testuser": {
        "phone": "1234567890",
        "otp": None,
        "first_name": None,
        "last_name": None,
    }
}


def generate_otp():
    return str(secrets.randbelow(10000)).zfill(4)

def send_otp(phone_number, otp):
    print(f"Sending OTP '{otp}' to phone number {phone_number}")


@app.post("/login/phone-number/")
def enter_phone_number(phone: str = Form(...)):
    # Check if the phone number exists in the fake user database
    user = next((user for user in fake_users_db.values() if user["phone"] == phone), None)
    if not user:
        raise HTTPException(status_code=401, detail="Phone number not registered")

    # Generate an OTP and store it in the user's data
    otp = generate_otp()
    user["otp"] = otp
    send_otp(phone, otp)

    return {"message": "OTP sent successfully"}

@app.post("/login/otp/")
def enter_otp(otp: str = Form(...), token: str = Depends(oauth2_scheme)):
    # Verify the OTP against the user's stored OTP
    user = next((user for user in fake_users_db.values() if user["otp"] == otp), None)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid OTP")

    # Generate a JWT token and send it back to the user
    jwt_token = jwt.encode({"sub": user["phone"], "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, "secret_key")
    return {"access_token": jwt_token, "token_type": "bearer"}

@app.post("/login/name/")
def enter_name(first_name: str = Form(...), last_name: str = Form(...), token: str = Depends(oauth2_scheme)):
    # Verify the token and get the user associated with the provided phone number
    phone_number = jwt.decode(token, "secret_key")["sub"]
    user = fake_users_db.get(phone_number)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token or user not found")

    # Store the first name and last name in the user's data
    user["first_name"] = first_name
    user["last_name"] = last_name

    return {"message": "Name information saved successfully"}
