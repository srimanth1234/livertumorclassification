# Import necessary modules
import pyrebase
import requests
from flask import Flask, flash, redirect, render_template, request, session, abort, url_for
from datetime import datetime
from werkzeug.utils import secure_filename
import os
import re
from flask import send_from_directory
from flask import Flask, render_template, request
import numpy as np
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing import image
import tensorflow as tf
from tensorflow.keras.applications.resnet50 import preprocess_input
from werkzeug.utils import secure_filename as werkzeug_secure_filename
from PIL import Image
# app = Flask(name)

# Load your pre-trained model


# Create a new Flask application
app = Flask(__name__)
# Set the secret key for the Flask app. This is used for session security.
app.secret_key = "123456789"

model = load_model('my_mode_opt.h5')
try:
    if model:
        print("Model loaded successfully.")
        # print(model.summary())
    else:
        print("Failed to load the model.")
except Exception as e:
    print("An error occurred while loading the model:", str(e))
# print(model.summary())

# Configuration for Firebase
config = {
    "apiKey": "AIzaSyAvj4DbCYaFdcEmrpSFTv57QuG_UMID8AA",
    "authDomain": "login-f1b09.firebaseapp.com",
    "databaseURL": "https://login-f1b09-default-rtdb.firebaseio.com",
    "storageBucket": "login-f1b09.appspot.com"
}

def preprocess_single_image(img_path):
    img = image.load_img(img_path, target_size=(512, 512))
    img_array = image.img_to_array(img)
    img_array = np.expand_dims(img_array, axis=0)
    img_array = preprocess_input(img_array)
    return img_array

# Set the upload folder (make sure this folder exists in your project)
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Check if the uploads folder exists; create it if not
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Initialize Firebase
firebase = pyrebase.initialize_app(config)

# Get reference to the auth service and database service
auth = firebase.auth()
db = firebase.database()

@app.route('/uploads/<name>:name')
def download_file(name):
    return send_from_directory(app.config["UPLOAD_FOLDER"], name)

# Route for the login page
@app.route("/")
def login():
    return render_template("login.html")

# Route for the signup page
@app.route("/signup")
def signup():
    return render_template("signup.html")

@app.route('/about')
def about():
    return render_template('about.html') 

# Route for the welcome page
@app.route("/welcome")
def welcome():
    # Check if user is logged in
    if session.get("is_logged_in", False):
        return render_template("welcome.html", email=session["email"], name=session["name"])
    else:
        # If user is not logged in, redirect to login page
        return redirect(url_for('login'))
    
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

    
""" @app.route('/upload', methods=['POST'])
def upload():
    # Get the uploaded file from the request
    img_file = request.files['file']

    if img_file and allowed_file(img_file.filename):
        # Generate a secure filename to avoid potential security issues
        filename = secure_filename(img_file.filename)

        # Save the uploaded file to the uploads folder
        img_path = os.path.join(UPLOAD_FOLDER,filename)
        print(img_path)
        img_file.save(img_path)

    # Preprocess the uploaded image
        img_array = preprocess_single_image(img_path)

    # Make predictions on the preprocessed image
        predictions = model.predict(img_array)

    # Interpret the predictions for multi-class classification
        class_labels = ['normal', 'malignant', 'benign']
        predicted_class_index = np.argmax(predictions)
        predicted_class_label = class_labels[predicted_class_index]

    # Process prediction result (e.g., get class labels)
    # ...

        return render_template('welcome.html', img_path=img_path,prediction=predicted_class_label)

    flash('Invalid file format. Allowed formats are: png, jpg, jpeg, gif')
    return redirect(url_for('welcome')) """

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        img_file = request.files.get('file')
        if img_file and allowed_file(img_file.filename):
            filename = secure_filename(img_file.filename)
            img_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            img_file.save(img_path)

            img_array = preprocess_single_image(img_path)
            predictions = model.predict(img_array)
            class_labels = ['normal', 'malignant', 'benign']
            predicted_class_index = np.argmax(predictions)
            predicted_class_label = class_labels[predicted_class_index]

            return render_template('welcome.html', img_path=img_path, prediction=predicted_class_label)
        else:
            if not img_file:
                flash('No file selected', 'error')
            else:
                flash('Invalid file format. Allowed formats are: png, jpg, jpeg, gif', 'error')
            return redirect(url_for('welcome'))

    # GET method: show the upload form or result of flash messages
    return render_template('welcome.html')


# Function to check password strength
def check_password_strength(password):
    # At least one lower case letter, one upper case letter, one digit, one special character, and at least 8 characters long
    return re.match(r'^(?=.*\d)(?=.*[!@#$%^&*])(?=.*[a-z])(?=.*[A-Z]).{8,}$', password) is not None

# Route for login result
@app.route("/result", methods=["POST", "GET"])
def result():
    if request.method == "POST":
        result = request.form
        email = result["email"]
        password = result["pass"]
        try:
            # Authenticate user
            user = auth.sign_in_with_email_and_password(email, password)
            session["is_logged_in"] = True
            session["email"] = user["email"]
            session["uid"] = user["localId"]
            # Fetch user data
            data = db.child("users").get().val()
            # Update session data
            if data and session["uid"] in data:
                session["name"] = data[session["uid"]]["name"]
                # Update last login time
                db.child("users").child(session["uid"]).update({"last_logged_in": datetime.now().strftime("%m/%d/%Y, %H:%M:%S")})
            else:
                session["name"] = "User"
            # Redirect to welcome page
            return redirect(url_for('welcome'))
        except Exception as e:
            print("Error occurred: ", e)
            error_message = "Incorrect email or password. Please try again."
            return render_template('login.html', error=error_message)
    else:
        # If user is logged in, redirect to welcome page
        if session.get("is_logged_in", False):
            return redirect(url_for('welcome'))
        else:
            return redirect(url_for('login'))


# Route for user registration
@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == "POST":
        result = request.form
        email = result["email"]
        password = result["pass"]
        name = result["name"]
        if not check_password_strength(password):
            print("Password does not meet strength requirements")
            return redirect(url_for('signup'))
        try:
            # Try to create a user account
            auth.create_user_with_email_and_password(email, password)
            # If successful, authenticate user
            user = auth.sign_in_with_email_and_password(email, password)
            session["is_logged_in"] = True
            session["email"] = user["email"]
            session["uid"] = user["localId"]
            session["name"] = name
            # Save user data
            data = {"name": name, "email": email, "last_logged_in": datetime.now().strftime("%m/%d/%Y, %H:%M:%S")}
            db.child("users").child(session["uid"]).set(data)
            return redirect(url_for('welcome'))
        except Exception as e:
            # If an error occurs during registration, check if it's because of an existing email
            error_message = str(e)
            if "EMAIL_EXISTS" in error_message:
                flash('An account with this email already exists. Please login.', 'error')
                return redirect(url_for('login'))
            else:
                print("Error occurred during registration: ", e)
                flash('An error occurred during registration. Please try again.', 'error')
                return redirect(url_for('signup'))
    else:
        # If user is already logged in, redirect to welcome page
        if session.get("is_logged_in", False):
            return redirect(url_for('welcome'))
        else:
            return redirect(url_for('signup'))

# Route for password reset
@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        email = request.form["email"]
        try:
            # Send password reset email
            auth.send_password_reset_email(email)
            return render_template("reset_password_done.html")  # Show a page telling user to check their email
        except Exception as e:
            print("Error occurred: ", e)
            return render_template("reset_password.html", error="An error occurred. Please try again.")  # Show error on reset password page
    else:
        return render_template("reset_password.html")  # Show the password reset page

# Route for logout
@app.route("/logout")
def logout():
    # Update last logout time
    db.child("users").child(session["uid"]).update({"last_logged_out": datetime.now().strftime("%m/%d/%Y, %H:%M:%S")})
    session["is_logged_in"] = False
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)