import eventlet
eventlet.monkey_patch()

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import json, os, uuid, datetime, hashlib
from functools import wraps
from passlib.hash import pbkdf2_sha256
from fpdf import FPDF


# ------------------- INITIAL SETUP -------------------

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-very-secret-key!')
socketio = SocketIO(app, cors_allowed_origins="*")

DATA_DIR = "data"
users_file = os.path.join(DATA_DIR, "users.json")

# Create data folder if not exists
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

# ------------------- HELPER FUNCTIONS -------------------

def load_json(file, default):
    """Load JSON safely, else recreate file with default"""
    if os.path.exists(file):
        try:
            with open(file, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"⚠️ {file} corrupted, recreating...")
    with open(file, "w") as f:
        json.dump(default, f, indent=4)
    return default

def save_json(file, data):
    """Save JSON data"""
    with open(file, "w") as f:
        json.dump(data, f, indent=4)

# ------------------- DEFAULT USERS -------------------

# It's highly recommended to move user data to a database.
# For this example, we'll hash the default admin password.
users = load_json(
    users_file,
    {
        "admin": {
            "id": str(uuid.uuid4()),
            "username": "admin",
            "password": pbkdf2_sha256.hash("admin123"),
            "role": "superadmin",
            "created_at": str(datetime.datetime.now()),
            "token": None  # token will be stored here after login
        },
        "lab_tech": {
            "id": str(uuid.uuid4()),
            "username": "lab_tech",
            "password": pbkdf2_sha256.hash("lab123"),
            "role": "lab",
            "created_at": str(datetime.datetime.now()),
            "token": None
        }
    }
)

# For faster token lookups
token_to_user = {u['token']: u for u in users.values() if u.get('token')}

# ------------------- AUTH DECORATOR -------------------

def token_required(f):
    """Decorator to check if user token is valid"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            try:
                token = request.headers["Authorization"].split(" ")[1]
            except:
                return jsonify({"error": "Invalid Authorization header"}), 401
        if not token:
            return jsonify({"error": "Token missing"}), 401

        current_user = token_to_user.get(token)
        if not current_user:
            return jsonify({"error": "Invalid token"}), 401

        return f(current_user, *args, **kwargs)
    return decorated

# ------------------- LOGIN -------------------

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    # Check users.json for all roles
    user = users.get(username)
    if user and pbkdf2_sha256.verify(password, user.get("password")):
        token = str(uuid.uuid4())
        user["token"] = token
        token_to_user[token] = user # Update our lookup map
        save_json(users_file, users) # This line was correct, no change needed but confirming
        return jsonify({**user, "message": f"Welcome {username}"})

    # Check patients.json for patient login
    patients = load_patients()
    patient_data = next((p for p in patients.values() if p.get("username") == username), None)

    if patient_data and pbkdf2_sha256.verify(password, patient_data.get("password")):
            token = str(uuid.uuid4())
            # Create a temporary user session for the patient without saving to users.json
            # This prevents overwriting real users (doctors, admins).
            # The token is validated by iterating through this in-memory 'users' dict for the request lifecycle.
            users[username] = { # This adds it to the in-memory dict for the token_required decorator
                "id": patient_data["id"],
                "username": username,
                "password": patient_data["password"], # Pass the hash for verification
                "role": "patient",
                "token": token
            }
            token_to_user[token] = users[username] # Add temporary patient session to lookup map
            # Return a consistent user object, similar to other roles
            patient_response_data = {
                "id": patient_data["id"],
                "username": username,
                "role": "patient",
                "token": token,
                "message": f"Welcome {username}",
            }
            return jsonify(patient_response_data)

    return jsonify({"error": "Invalid username or password"}), 401

@app.route("/admin/overview", methods=["GET"])
@token_required
def admin_overview(current_user):
    if current_user["role"] != "superadmin":
        return jsonify({"error": "Unauthorized"}), 403

    total_doctors = len([u for u in users.values() if u["role"] == "doctor"])
    total_receptionists = len([u for u in users.values() if u["role"] == "reception"])
    return jsonify({
        "total_users": len(users),
        "doctors": total_doctors,
        "receptionists": total_receptionists
    })

# ------------------- PATIENT REGISTRATION -------------------

PATIENTS_FILE = os.path.join(DATA_DIR, "patients.json")

def load_patients():
    return load_json(PATIENTS_FILE, {})

def save_patients(patients):
    save_json(PATIENTS_FILE, patients)

@app.route("/register", methods=["POST"])
def register_patient():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    # Explicitly get required fields, ignoring extras like confirmPassword
    required_fields = ["name", "age", "gender", "fees", "username", "password", "doctor"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400

    # Validate data types
    try:
        age = int(data["age"])
        fees = float(data["fees"])
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid data type for age or fees"}), 400

    # Check for existing username
    if data["username"] in users or any(p.get("username") == data["username"] for p in load_patients().values()):
        return jsonify({"error": "Username already exists"}), 409

    hashed_password = pbkdf2_sha256.hash(data["password"])

    patients = load_patients()
    patient_id = str(uuid.uuid4())
    patients[patient_id] = {
        "id": patient_id,
        "name": data.get("name"),
        "age": age,
        "gender": data.get("gender"),
        "fees": fees,
        "username": data.get("username"),
        "password": hashed_password,
        "doctor": data.get("doctor"),
        "created_at": str(datetime.datetime.now()),
        "records": []
    }
    save_patients(patients)
    return jsonify({
        "message": f"Patient '{data['name']}' registered successfully!",
        "patient_id": patient_id,
        "username": data["username"],
        "fees": fees
    }), 201

# ------------------- PATIENT LIST -------------------

@app.route("/patients", methods=["GET"])
def get_patients():
    patients = load_patients()
    return jsonify(list(patients.values()))

@app.route("/patients/<string:patient_id>", methods=["GET"])
@token_required
def get_patient(current_user, patient_id):
    """Endpoint to get a single patient by ID."""
    patients = load_patients()
    patient = patients.get(patient_id)
    if not patient:
        return jsonify({"error": "Patient not found"}), 404
    return jsonify(patient)

@app.route("/patients/me", methods=["GET"])
@token_required
def get_current_patient(current_user):
    """Endpoint for a logged-in patient to get their own profile."""
    if current_user.get("role") != "patient":
        return jsonify({"error": "User is not a patient"}), 403

    patients = load_patients()
    patient = patients.get(current_user.get("id"))

    if not patient:
        return jsonify({"error": "Patient profile not found"}), 404
    return jsonify(patient)

# ------------------- DOCTOR LIST -------------------

@app.route("/doctors", methods=["GET"])
def get_doctors():
    doctor_list = [u for u in users.values() if u.get("role") == "doctor"]
    return jsonify(doctor_list)

@app.route("/doctors/my-patients", methods=["GET"])
@token_required
def get_my_patients(current_user):
    """Endpoint for a doctor to get only their assigned patients."""
    if current_user.get("role") != "doctor":
        return jsonify({"error": "Unauthorized"}), 403
    
    all_patients = load_patients().values()
    doctor_patients = [p for p in all_patients if p.get("doctor") == current_user.get("username")]
    return jsonify(doctor_patients)

@app.route("/doctors/me/profile", methods=["PUT"])
@token_required
def update_doctor_profile(current_user):
    """Endpoint for a doctor to update their profile, like consultation fee."""
    if current_user.get("role") != "doctor":
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()
    new_fee = data.get("consultation_fee")

    if new_fee is None:
        return jsonify({"error": "Consultation fee is required"}), 400

    # Update the in-memory user object and save to file
    doctor_username = current_user.get("username")
    users[doctor_username]["consultation_fee"] = float(new_fee)
    save_json(users_file, users)

    return jsonify({"message": "Profile updated successfully", "user": users[doctor_username]})

# ------------------- ADD PATIENT RECORD -------------------

@app.route("/add_record", methods=["POST"])
def add_record():
    data = request.get_json()
    patient_id = data.get("patient_id")
    record = data.get("record")
    doctor = data.get("doctor")

    if not all([patient_id, record, doctor]):
        return jsonify({"error": "Missing data"}), 400

    patients = load_patients()
    patient = patients.get(patient_id)
    if not patient:
        return jsonify({"error": "Patient not found"}), 404

    if "records" not in patient:
        patient["records"] = []

    patient["records"].append({
        "doctor": doctor,
        "record": record,
        "timestamp": str(datetime.datetime.now())
    })

    patients[patient_id] = patient
    save_patients(patients)

    return jsonify({"message": "Record added successfully"})

# ------------------- APPOINTMENT MANAGEMENT -------------------

APPOINTMENTS_FILE = os.path.join(DATA_DIR, "appointments.json")

def load_appointments():
    return load_json(APPOINTMENTS_FILE, {})

def save_appointments(appointments):
    save_json(APPOINTMENTS_FILE, appointments)

@app.route("/appointments", methods=["POST"])
@token_required
def book_appointment(current_user):
    """Endpoint for patients to book an appointment."""
    user_role = current_user.get("role")
    if user_role not in ["patient", "reception"]:
        return jsonify({"error": "Unauthorized to book appointments"}), 403

    data = request.get_json()
    doctor_id = data.get("doctor_id")
    date = data.get("date")
    time = data.get("time")
    patient_id = None
    patient_name = None

    if user_role == "patient":
        patient_id = current_user["id"]
        patient_name = users.get(current_user["username"], {}).get("name", current_user["username"])
    elif user_role == "reception":
        patient_id = data.get("patient_id")
        if not patient_id:
            return jsonify({"error": "Patient ID is required for receptionist booking"}), 400
        patients = load_patients()
        patient_name = patients.get(patient_id, {}).get("name", "Unknown Patient")

    if not all([doctor_id, date, time, patient_id]):
        return jsonify({"error": "Missing appointment data"}), 400

    appointments = load_appointments()
    appointment_id = str(uuid.uuid4())

    # --- NEW: Create a bill immediately upon booking ---
    # Find the doctor from the main users list by their ID
    doctor = next((u for u in users.values() if u.get("id") == doctor_id and u.get("role") == "doctor"), None)
    if not doctor:
        return jsonify({"error": "Selected doctor not found"}), 404

    consultation_fee = doctor.get("consultation_fee", 250) # Default fee
    bills = load_bills()
    bill_id = str(uuid.uuid4())
    bills[bill_id] = {
        "id": bill_id,
        "patient_id": patient_id,
        "amount": consultation_fee,
        "description": f"Consultation with Dr. {doctor.get('username')}",
        "status": "Unpaid",
        "created_at": str(datetime.datetime.now()),
        "created_by": current_user["id"],
        "appointment_id": appointment_id # Link bill to appointment
    }
    save_bills(bills)

    appointments[appointment_id] = {
        "id": appointment_id,
        "patient_id": patient_id,
        "patient_name": patient_name,
        "doctor_id": doctor_id,
        "bill_id": bill_id, # Link appointment to bill
        "date": date,
        "time": time,
        "status": "Awaiting Payment", # New initial status
        "created_at": str(datetime.datetime.now())
    }
    save_appointments(appointments)

    # Note: Doctor is NOT notified until payment is made.
    # Patient is expected to pay the newly created bill.

    return jsonify({"message": "Appointment requested. Please complete payment to confirm.", "appointment_id": appointment_id, "bill_id": bill_id}), 201

def _check_and_cancel_expired_appointments():
    """
    Iterates through appointments and cancels any pending ones
    where the appointment time has passed.
    """
    appointments = load_appointments()
    now = datetime.datetime.now()
    changed = False
    for app_id, appointment in appointments.items():
        if appointment.get("status") in ["Pending", "Awaiting Payment"]:
            try:
                app_datetime_str = f"{appointment['date']} {appointment['time']}"
                app_datetime = datetime.datetime.strptime(app_datetime_str, "%Y-%m-%d %H:%M")
                if now > app_datetime:
                    appointment["status"] = "Cancelled"
                    changed = True
            except (ValueError, KeyError):
                continue # Skip if date/time format is wrong or missing
    if changed:
        save_appointments(appointments)

@app.route("/patients/me/appointments", methods=["GET"])
@token_required
def get_my_appointments(current_user):
    """Endpoint for a patient to get only their appointments."""
    if current_user.get("role") != "patient":
        return jsonify({"error": "Unauthorized"}), 403
    appointments = load_appointments()
    _check_and_cancel_expired_appointments() # Check before returning
    user_appointments = [app for app in appointments.values() if app.get("patient_id") == current_user.get("id")]
    return jsonify(user_appointments)

@app.route("/appointments", methods=["GET"])
@token_required
def get_appointments(current_user):
    """Endpoint to get appointments based on user role."""
    _check_and_cancel_expired_appointments() # Check before returning
    appointments = load_appointments()
    user_role = current_user.get("role")
    user_id = current_user.get("id")

    if user_role == "patient":
        user_appointments = [app for app in appointments.values() if app.get("patient_id") == user_id]
        return jsonify(user_appointments)
    elif user_role == "doctor":
        doctor_appointments = [app for app in appointments.values() if app.get("doctor_id") == user_id]
        return jsonify(doctor_appointments)
    elif user_role in ["superadmin", "reception"]:
        return jsonify(list(appointments.values()))
    
    return jsonify({"error": "Unauthorized to view appointments"}), 403

@app.route("/appointments/<string:appointment_id>", methods=["PUT"])
@token_required
def update_appointment(current_user, appointment_id):
    """Endpoint for doctors to update appointment status."""
    if current_user.get("role") not in ["doctor", "superadmin"]:
        return jsonify({"error": "Unauthorized"}), 403
    
    data = request.get_json()
    new_status = data.get("status")

    if not new_status:
        return jsonify({"error": "New status is required"}), 400

    appointments = load_appointments()
    appointment = appointments.get(appointment_id)

    if not appointment:
        return jsonify({"error": "Appointment not found"}), 404

    appointment["status"] = new_status
    save_appointments(appointments)

    # --- WebSocket Notification to Patient ---
    patient_id = appointment.get("patient_id")
    patient_sid = user_sids.get(patient_id)
    if patient_sid:
        emit('new_notification', {'message': f'Your appointment on {appointment["date"]} has been {new_status}.'}, room=patient_sid, namespace='/')

    return jsonify({"message": f"Appointment {appointment_id} updated to {new_status}"})

# ------------------- BILLING & PAYMENTS -------------------

BILLS_FILE = os.path.join(DATA_DIR, "bills.json")

def load_bills():
    return load_json(BILLS_FILE, {})

def save_bills(bills):
    save_json(BILLS_FILE, bills)

@app.route("/bills", methods=["POST"])
@token_required
def create_bill(current_user):
    """Endpoint for doctors/admins to create a bill for a patient."""
    if current_user.get("role") not in ["doctor", "superadmin"]:
        return jsonify({"error": "Unauthorized to create bills"}), 403

    data = request.get_json()
    patient_id = data.get("patient_id")
    amount = data.get("amount")
    description = data.get("description")

    if not all([patient_id, amount, description]):
        return jsonify({"error": "Missing billing data"}), 400

    bills = load_bills()
    bill_id = str(uuid.uuid4())
    
    bills[bill_id] = {
        "id": bill_id,
        "patient_id": patient_id,
        "amount": amount,
        "description": description,
        "status": "Unpaid",
        "created_at": str(datetime.datetime.now()),
        "created_by": current_user["id"]
    }
    save_bills(bills)
    return jsonify({"message": "Bill created successfully", "bill_id": bill_id}), 201

@app.route("/patients/me/bills", methods=["GET"])
@token_required
def get_my_bills(current_user):
    """Endpoint for a patient to get only their bills."""
    if current_user.get("role") != "patient":
        return jsonify({"error": "Unauthorized"}), 403
    bills = load_bills()
    user_bills = [b for b in bills.values() if b.get("patient_id") == current_user.get("id")]
    return jsonify(user_bills)

@app.route("/bills", methods=["GET"])
@token_required
def get_bills(current_user):
    """Endpoint to get bills based on user role."""
    bills = load_bills()
    user_role = current_user.get("role")
    user_id = current_user.get("id")

    if user_role == "patient":
        user_bills = [b for b in bills.values() if b.get("patient_id") == user_id]
        return jsonify(user_bills)
    elif user_role in ["doctor", "superadmin"]:
        # For simplicity, doctors and admins can see all bills.
        # This could be refined for doctors to see only their patients' bills.
        return jsonify(list(bills.values()))
    
    return jsonify({"error": "Unauthorized"}), 403

@app.route("/bills/<string:bill_id>/pay", methods=["PUT"])
@token_required
def pay_bill(current_user, bill_id):
    """Endpoint for patients to pay a bill."""
    if current_user.get("role") != "patient":
        return jsonify({"error": "Only patients can pay bills"}), 403

    bills = load_bills()
    bill = bills.get(bill_id)

    if not bill or bill.get("patient_id") != current_user.get("id"):
        return jsonify({"error": "Bill not found or unauthorized"}), 404

    if bill["status"] == "Paid":
        return jsonify({"message": "Bill is already paid."})

    bill["status"] = "Paid"
    save_bills(bills)

    # --- NEW: Update appointment status and notify doctor after payment ---
    appointment_id = bill.get("appointment_id")
    if appointment_id:
        appointments = load_appointments()
        appointment = appointments.get(appointment_id)
        if appointment and appointment["status"] == "Awaiting Payment":
            appointment["status"] = "Pending" # Now it's pending for doctor's approval
            save_appointments(appointments)
            # Notify the doctor
            doctor_id = appointment.get("doctor_id")
            notify_user(doctor_id, f"New paid appointment request from {appointment.get('patient_name')}.")

    # --- NEW: Update lab test status and notify lab after payment ---
    lab_test_id = bill.get("lab_test_id")
    if lab_test_id:
        lab_tests = load_lab_tests()
        lab_test = lab_tests.get(lab_test_id)
        if lab_test and lab_test.get("status") == "Awaiting Payment":
            lab_test["status"] = "Awaiting Sample" # Ready for the lab
            save_lab_tests(lab_tests)
            # Notify all lab technicians
            lab_users = [u for u in users.values() if u.get("role") == "lab"]
            for lab_user in lab_users:
                notify_user(lab_user["id"], f"New lab test paid for patient. Ready for sample collection.")

    return jsonify({"message": f"Bill {bill_id} has been paid successfully"})

# ------------------- ADMIN - DOCTOR MANAGEMENT -------------------

@app.route("/admin/doctors", methods=["POST"])
@token_required
def add_doctor(current_user):
    """Admin endpoint to add a new doctor."""
    if current_user.get("role") != "superadmin":
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    specialization = data.get("specialization", "General Physician") # Default value

    if not all([username, password, specialization]):
        return jsonify({"error": "Username, password, and specialization are required"}), 400

    if username in users:
        return jsonify({"error": "Username already exists"}), 409

    hashed_password = pbkdf2_sha256.hash(password)
    users[username] = {
        "id": str(uuid.uuid4()),
        "username": username,
        "password": hashed_password,
        "specialization": specialization,
        "consultation_fee": 250, # Default fee
        "role": "doctor",
        "created_at": str(datetime.datetime.now()),
        "token": None
    }
    save_json(users_file, users)
    return jsonify({"message": f"Doctor '{username}' added successfully"}), 201

@app.route("/admin/doctors/<string:username>", methods=["DELETE"])
@token_required
def remove_doctor(current_user, username):
    """Admin endpoint to remove a doctor."""
    if current_user.get("role") != "superadmin":
        return jsonify({"error": "Unauthorized"}), 403

    if username in users and users[username].get("role") == "doctor":
        del users[username]
        save_json(users_file, users)
        return jsonify({"message": f"Doctor '{username}' removed successfully"})
    
    return jsonify({"error": "Doctor not found"}), 404

@app.route("/register_user", methods=["POST"])
@token_required
def register_user(current_user):
    """Admin endpoint to add a new user."""
    if current_user.get("role") != "superadmin":
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    role = data.get("role")

    if not all([username, password, role]):
        return jsonify({"error": "Username, password, and role are required"}), 400

    if username in users:
        return jsonify({"error": "Username already exists"}), 409

    hashed_password = pbkdf2_sha256.hash(password)
    users[username] = {
        "id": str(uuid.uuid4()),
        "username": username,
        "password": hashed_password,
        "role": role,
        "created_at": str(datetime.datetime.now()),
        "token": None
    }
    save_json(users_file, users)
    return jsonify({"message": f"User '{username}' added successfully"}), 201

# ------------------- PRESCRIPTION MANAGEMENT -------------------

PRESCRIPTIONS_FILE = os.path.join(DATA_DIR, "prescriptions.json")

def load_prescriptions():
    return load_json(PRESCRIPTIONS_FILE, {})

def save_prescriptions(prescriptions):
    save_json(PRESCRIPTIONS_FILE, prescriptions)

@app.route("/prescriptions", methods=["POST"])
@token_required
def create_prescription(current_user):
    """Endpoint for doctors to create a prescription."""
    if current_user.get("role") != "doctor":
        return jsonify({"error": "Only doctors can create prescriptions"}), 403

    data = request.get_json()
    patient_id = data.get("patient_id")
    medications = data.get("medications") # Text field for simplicity
    notes = data.get("notes")

    if not all([patient_id, medications]):
        return jsonify({"error": "Patient ID and medications are required"}), 400

    prescriptions = load_prescriptions()
    prescription_id = str(uuid.uuid4())
    
    prescriptions[prescription_id] = {
        "id": prescription_id,
        "patient_id": patient_id,
        "doctor_id": current_user["id"],
        "doctor_name": current_user["username"],
        "medications": medications,
        "notes": notes,
        "created_at": str(datetime.datetime.now())
    }
    save_prescriptions(prescriptions)

    # --- Automatically create a bill for the consultation ---
    patients = load_patients()
    patient = patients.get(patient_id)
    if patient:
        bills = load_bills()
        bill_id = str(uuid.uuid4())
        consultation_fee = patient.get("fees", 150) # Default fee if not found
        
        bills[bill_id] = {
            "id": bill_id,
            "patient_id": patient_id,
            "amount": consultation_fee,
            "description": "Doctor Consultation & Prescription",
            "status": "Unpaid",
            "created_at": str(datetime.datetime.now()),
            "created_by": current_user["id"],
            "prescription_id": prescription_id # Link bill to prescription
        }
        save_bills(bills)
        # Optionally, notify the patient about the new bill
        # This would require WebSocket implementation for patients

    return jsonify({"message": "Prescription created successfully", "prescription_id": prescription_id}), 201

@app.route("/patients/me/prescriptions", methods=["GET"])
@token_required
def get_my_prescriptions(current_user):
    """Endpoint for a patient to get only their prescriptions."""
    if current_user.get("role") != "patient":
        return jsonify({"error": "Unauthorized"}), 403
    prescriptions = load_prescriptions()
    user_prescriptions = [p for p in prescriptions.values() if p.get("patient_id") == current_user.get("id")]
    return jsonify(user_prescriptions)

@app.route("/prescriptions", methods=["GET"])
@token_required
def get_prescriptions(current_user):
    """Endpoint to get prescriptions based on user role."""
    prescriptions = load_prescriptions()
    user_role = current_user.get("role")
    user_id = current_user.get("id")

    if user_role == "patient":
        user_prescriptions = [p for p in prescriptions.values() if p.get("patient_id") == user_id]
        return jsonify(user_prescriptions)
    elif user_role == "doctor":
        doctor_prescriptions = [p for p in prescriptions.values() if p.get("doctor_id") == user_id]
        return jsonify(doctor_prescriptions)
    elif user_role == "superadmin":
        return jsonify(list(prescriptions.values()))
    
    return jsonify({"error": "Unauthorized"}), 403

class PDF(FPDF):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.watermark_text = "getwell soon gm health"

    def add_page(self, orientation=''):
        super().add_page(orientation)
        # --- Add Watermark ---
        self.set_font('Arial', 'B', 40)
        self.set_text_color(230, 230, 230) # Light gray
        self.rotate(45, x=self.w / 2, y=self.h / 2)
        self.text(x=self.w / 2 - 70, y=self.h / 2, txt=self.watermark_text)
        self.rotate(0)
        self.set_text_color(0, 0, 0) # Reset text color

@app.route("/prescriptions/<string:prescription_id>/download", methods=["GET"])
@token_required
def download_prescription(current_user, prescription_id):
    """Endpoint to generate and download a prescription as a PDF."""
    prescriptions = load_prescriptions()
    prescription = prescriptions.get(prescription_id)

    if not prescription:
        return jsonify({"error": "Prescription not found"}), 404

    # Authorization check
    user_role = current_user.get("role")
    user_id = current_user.get("id")
    if user_role == "patient" and prescription.get("patient_id") != user_id:
        return jsonify({"error": "Unauthorized"}), 403

    # --- NEW: Check if the associated bill is paid for patients ---
    if user_role == "patient":
        # Find the appointment bill, not a prescription-specific bill
        bills = load_bills()
        appointment_bill = next((b for b in bills.values() if b.get("appointment_id") == prescription.get("appointment_id")), None)

        if appointment_bill and appointment_bill.get("status") == "Unpaid":
            return jsonify({
                "error": "Payment required. Please pay the consultation bill to access this prescription.",
                "bill_id": appointment_bill.get("id"),
                "reason": "payment_required"
            }), 402 # HTTP 402 Payment Required

    # Fetch related data
    patients = load_patients()
    patient = patients.get(prescription.get("patient_id"))
    doctor = users.get(prescription.get("doctor_name"))

    if not patient or not doctor:
        return jsonify({"error": "Associated patient or doctor not found"}), 404

    # Generate PDF
    pdf = PDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    
    # Header
    pdf.cell(0, 10, "GM Block Chain Health", 0, 1, "C")
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, "pb road davangere", 0, 1, "C")
    pdf.ln(10)

    # Patient & Doctor Info
    pdf.set_font("Arial", "B", 12)
    pdf.cell(95, 8, f"Patient: {patient.get('name')}", 0, 0)
    pdf.cell(95, 8, f"Doctor: Dr. {doctor.get('username')}", 0, 1, "R")
    pdf.set_font("Arial", "", 12)
    pdf.cell(95, 8, f"Age: {patient.get('age')}, Gender: {patient.get('gender')}", 0, 0)
    pdf.cell(95, 8, f"Date: {datetime.datetime.fromisoformat(prescription.get('created_at')).strftime('%Y-%m-%d')}", 0, 1, "R")
    pdf.ln(10)

    # Prescription Body
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Prescription (Rx)", "B", 1)
    pdf.ln(5)
    
    pdf.set_font("Arial", "", 12)
    pdf.multi_cell(0, 8, f"Medications:\n{prescription.get('medications')}")
    pdf.ln(5)
    
    if prescription.get("notes"):
        pdf.set_font("Arial", "I", 12)
        pdf.multi_cell(0, 8, f"Notes:\n{prescription.get('notes')}")

    # Create response
    pdf_output = pdf.output(dest='S').encode('latin-1')
    response = make_response(pdf_output)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=prescription_{prescription_id}.pdf'
    return response

# ------------------- MEDICAL HISTORY -------------------

@app.route("/patients/<string:patient_id>/history", methods=["GET"])
@token_required
def get_patient_history(current_user, patient_id):
    """Endpoint to get a patient's complete medical history."""
    user_role = current_user.get("role")
    user_id = current_user.get("id")

    # Authorize: patient can see their own history, doctors/admins can see any.
    if user_role == "patient" and user_id != patient_id:
        return jsonify({"error": "Unauthorized"}), 403
    
    if user_role not in ["patient", "doctor", "superadmin"]:
        return jsonify({"error": "Unauthorized"}), 403

    history = []
    
    # 1. General Records from patient file
    patients = load_patients()
    patient = patients.get(patient_id)
    if patient and "records" in patient:
        for record in patient["records"]:
            history.append({**record, "type": "Note", "date": record.get("timestamp")})

    # 2. Appointments
    appointments = load_appointments()
    for app in appointments.values():
        if app.get("patient_id") == patient_id:
            history.append({**app, "type": "Appointment"})

    # 3. Prescriptions
    prescriptions = load_prescriptions()
    for pr in prescriptions.values():
        if pr.get("patient_id") == patient_id:
            history.append({**pr, "type": "Prescription", "date": pr.get("created_at")})

    # 4. Bills
    bills = load_bills()
    for bill in bills.values():
        if bill.get("patient_id") == patient_id:
            history.append({**bill, "type": "Bill", "date": bill.get("created_at")})
            
    # 5. Lab Tests
    lab_tests = load_lab_tests()
    for test in lab_tests.values():
        if test.get("patient_id") == patient_id:
            history.append({**test, "type": "LabTest"})

    # Sort history chronologically, newest first
    sorted_history = sorted(history, key=lambda x: x.get("date", ""), reverse=True)
    
    return jsonify(sorted_history)

# ------------------- LAB TEST MANAGEMENT (IMPROVED) -------------------

LAB_TESTS_FILE = os.path.join(DATA_DIR, "lab_tests.json")
LAB_TESTS_CATALOG_FILE = os.path.join(DATA_DIR, "lab_tests_catalog.json")

def load_lab_tests():
    return load_json(LAB_TESTS_FILE, {})

def save_lab_tests(tests):
    save_json(LAB_TESTS_FILE, tests)

def load_lab_tests_catalog():
    return load_json(LAB_TESTS_CATALOG_FILE, {})

@app.route("/lab-tests/catalog", methods=["GET"])
@token_required
def get_lab_tests_catalog(current_user):
    """Endpoint to get the list of available lab tests."""
    catalog = load_lab_tests_catalog()
    return jsonify(catalog)

@app.route("/lab-tests", methods=["POST"])
@token_required
def request_lab_test(current_user):
    """Endpoint for DOCTORS to request a lab test for a patient."""
    if current_user.get("role") != "doctor":
        return jsonify({"error": "Only doctors can request lab tests"}), 403

    data = request.get_json()
    patient_id = data.get("patient_id")
    test_id_from_catalog = data.get("test_id") # Changed from test_name

    if not all([patient_id, test_id_from_catalog]):
        return jsonify({"error": "Patient ID and a selected test are required"}), 400

    # Get test details from the catalog
    catalog = load_lab_tests_catalog()
    test_details = catalog.get(test_id_from_catalog)
    if not test_details:
        return jsonify({"error": "Invalid test selected"}), 400

    test_name = test_details.get("name")
    test_fee = test_details.get("fee")

    # Create the lab test with 'Awaiting Payment' status
    tests = load_lab_tests()
    test_id = str(uuid.uuid4())
    tests[test_id] = {
        "id": test_id,
        "patient_id": patient_id,
        "doctor_id": current_user["id"],
        "doctor_name": current_user["username"],
        "test_name": test_name,
        "status": "Awaiting Payment",
        "results": None,
        "date_requested": str(datetime.datetime.now()),
        "date_completed": None
    }
    
    # Create a corresponding bill for the lab test
    bills = load_bills()
    bill_id = str(uuid.uuid4())
    bills[bill_id] = {
        "id": bill_id,
        "patient_id": patient_id,
        "amount": test_fee,
        "description": f"Lab Test: {test_name}",
        "status": "Unpaid",
        "created_at": str(datetime.datetime.now()),
        "created_by": current_user["id"],
        "lab_test_id": test_id # Link bill to lab test
    }
    save_bills(bills)
    save_lab_tests(tests)

    # Notify patient about the new bill
    notify_user(patient_id, f"A new bill for lab test '{test_name}' has been created.")

    return jsonify({"message": "Lab test requested. Awaiting patient payment.", "test_id": test_id, "bill_id": bill_id}), 201

@app.route("/lab-tests", methods=["GET"])
@token_required
def get_lab_tests(current_user):
    """Endpoint to get lab tests based on user role."""
    tests = load_lab_tests()
    user_role = current_user.get("role")
    user_id = current_user.get("id")

    # Enhance with patient and doctor names for frontend display
    all_patients = load_patients()
    all_users = users

    for test in tests.values():
        patient = all_patients.get(test.get("patient_id"))
        test["patient_name"] = patient.get("name") if patient else "Unknown Patient"
        doctor = next((u for u in all_users.values() if u.get("id") == test.get("doctor_id")), None)
        test["doctor_name"] = doctor.get("username") if doctor else "N/A"

    if user_role == "patient":
        return jsonify([t for t in tests.values() if t.get("patient_id") == user_id])
    elif user_role == "doctor":
        return jsonify([t for t in tests.values() if t.get("doctor_id") == user_id])
    elif user_role in ["lab", "superadmin"]:
        return jsonify(list(tests.values()))
    
    return jsonify({"error": "Unauthorized"}), 403

@app.route("/lab-tests/<string:test_id>", methods=["PUT"])
@token_required
def update_lab_test(current_user, test_id):
    """Endpoint for LAB TECHNICIANS to update test status and results."""
    if current_user.get("role") != "lab":
        return jsonify({"error": "Only lab technicians can update tests"}), 403

    data = request.get_json()
    tests = load_lab_tests()
    test = tests.get(test_id)

    if not test:
        return jsonify({"error": "Lab test not found"}), 404

    # Update status and results
    new_status = data.get("status")
    if new_status:
        test["status"] = new_status
    
    new_results = data.get("results")
    if new_results:
        test["results"] = new_results
        test["status"] = "Completed" # Automatically set to completed when results are added
        test["date_completed"] = str(datetime.datetime.now())
        # Notify patient and doctor
        notify_user(test["patient_id"], f"Your lab report for '{test['test_name']}' is ready.")
        notify_user(test["doctor_id"], f"Lab report for patient {test.get('patient_name')} is ready.")

    save_lab_tests(tests)
    return jsonify({"message": "Lab test updated successfully", "test": test})

class LabPDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 16)
        self.cell(0, 10, 'GM Block Chain Health', 0, 1, 'C')
        self.set_font('Arial', '', 10)
        self.cell(0, 8, 'Lab & Diagnostics Center', 0, 1, 'C')
        self.cell(0, 8, 'pb road davangere', 0, 1, 'C')
        self.set_line_width(0.5)
        self.line(10, 35, 200, 35)
        self.ln(15)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')
        self.set_font('Arial', '', 8)
        self.cell(0, 10, 'Generated on: ' + str(datetime.datetime.now()), 0, 0, 'R')

@app.route("/lab-tests/<string:test_id>/download", methods=["GET"])
@token_required
def download_lab_report(current_user, test_id):
    """Endpoint to generate and download a lab test report as a PDF."""
    tests = load_lab_tests()
    test = tests.get(test_id)

    if not test:
        return jsonify({"error": "Lab test not found"}), 404

    # Authorization: Patient, Doctor, Lab, or Admin
    user_role = current_user.get("role")
    user_id = current_user.get("id")
    if not (user_role in ["lab", "superadmin"] or 
            (user_role == "patient" and test.get("patient_id") == user_id) or 
            (user_role == "doctor" and test.get("doctor_id") == user_id)):
        return jsonify({"error": "Unauthorized to view this report"}), 403

    if test.get("status") != "Completed":
        return jsonify({"error": "Lab report is not yet available."}), 400

    # Fetch related data
    patient = load_patients().get(test.get("patient_id"))
    doctor = next((u for u in users.values() if u.get("id") == test.get("doctor_id")), None)

    if not patient or not doctor:
        return jsonify({"error": "Associated patient or doctor not found"}), 404

    # Generate PDF
    pdf = LabPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, 'Laboratory Test Report', 0, 1, 'C')
    pdf.ln(10)

    # Patient & Test Info
    pdf.set_font('Arial', 'B', 11)
    pdf.cell(40, 8, 'Patient Name:')
    pdf.set_font('Arial', '', 11)
    pdf.cell(90, 8, patient.get('name'))
    pdf.set_font('Arial', 'B', 11)
    pdf.cell(30, 8, 'Test ID:')
    pdf.set_font('Arial', '', 11)
    pdf.cell(30, 8, test_id)
    pdf.ln()

    pdf.set_font('Arial', 'B', 11)
    pdf.cell(40, 8, 'Patient ID:')
    pdf.set_font('Arial', '', 11)
    pdf.cell(90, 8, patient.get('id'))
    pdf.set_font('Arial', 'B', 11)
    pdf.cell(30, 8, 'Date Reported:')
    pdf.set_font('Arial', '', 11)
    pdf.cell(30, 8, datetime.datetime.fromisoformat(test.get('date_completed')).strftime('%Y-%m-%d'))
    pdf.ln()

    pdf.set_font('Arial', 'B', 11)
    pdf.cell(40, 8, 'Referring Doctor:')
    pdf.set_font('Arial', '', 11)
    pdf.cell(0, 8, f"Dr. {doctor.get('username')}")
    pdf.ln(15)

    # Test Results Body
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, f"Test: {test.get('test_name')}", 'B', 1)
    pdf.ln(5)
    
    pdf.set_font("Arial", "", 11)
    pdf.multi_cell(0, 8, f"Results:\n{test.get('results')}")
    pdf.ln(10)

    # Create response
    pdf_output = pdf.output(dest='S').encode('latin-1')
    response = make_response(pdf_output)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=lab_report_{test_id}.pdf'
    return response

# ------------------- ADMIN - INVENTORY MANAGEMENT -------------------

inventory_file = os.path.join(DATA_DIR, "inventory.json")

def load_inventory():
    return load_json(inventory_file, {})

def save_inventory(inventory):
    save_json(inventory_file, inventory)

@app.route("/admin/inventory", methods=["GET"])
@token_required
def get_inventory(current_user):
    """Admin endpoint to get all inventory items."""
    # Allow more roles to view inventory
    allowed_roles = ["superadmin", "doctor", "reception", "lab"]
    if current_user.get("role") not in allowed_roles:
        return jsonify({"error": "Unauthorized to view inventory"}), 403
    inventory = load_inventory()
    return jsonify(list(inventory.values()))

@app.route("/admin/inventory", methods=["POST"])
@token_required
def add_inventory_item(current_user):
    """Admin endpoint to add a new item to the inventory."""
    if current_user.get("role") != "superadmin":
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()
    name = data.get("name")
    quantity = data.get("quantity")
    category = data.get("category")

    if not all([name, quantity, category]):
        return jsonify({"error": "Name, quantity, and category are required"}), 400

    inventory = load_inventory()
    item_id = str(uuid.uuid4())
    inventory[item_id] = {
        "id": item_id,
        "name": name,
        "quantity": int(quantity),
        "category": category,
        "last_updated": str(datetime.datetime.now())
    }
    save_inventory(inventory)
    return jsonify({"message": "Inventory item added successfully", "item": inventory[item_id]}), 201

@app.route("/admin/inventory/<string:item_id>", methods=["PUT"])
@token_required
def update_inventory_item(current_user, item_id):
    """Admin endpoint to update an inventory item's quantity."""
    if current_user.get("role") != "superadmin":
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()
    inventory = load_inventory()
    if item_id not in inventory:
        return jsonify({"error": "Item not found"}), 404

    inventory[item_id]["quantity"] = int(data.get("quantity", inventory[item_id]["quantity"]))
    inventory[item_id]["last_updated"] = str(datetime.datetime.now())
    save_inventory(inventory)
    return jsonify({"message": "Inventory item updated", "item": inventory[item_id]})

# ------------------- WebSocket Events -------------------

user_sids = {} # Maps user_id to their session ID

@socketio.on('connect')
def handle_connect():
    print(f'Client connected: {request.sid}')
    emit("user_connected", {"sid": request.sid}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    print(f'Client disconnected: {request.sid}')
    for user_id, sid in user_sids.items():
        if sid == request.sid:
            del user_sids[user_id]
            break

@socketio.on('register_user')
def handle_register_user(data):
    user_id = data.get('user_id')
    if user_id:
        user_sids[user_id] = request.sid
        print(f"Registered user {user_id} with SID {request.sid}")
        emit("user_connected", {"user_id": user_id}, broadcast=True)

def notify_user(user_id, message):
    """Helper to send a WebSocket notification to a specific user."""
    sid = user_sids.get(user_id)
    if sid:
        socketio.emit('new_notification', {'message': message}, room=sid)

# ------------------- RUN SERVER -------------------

if __name__ == "__main__":
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
