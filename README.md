Generated markdown
# Titiksha Hospitals - Full-Stack Appointment Management System

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-3776AB.svg?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/Django-4.2-092E20.svg?style=for-the-badge&logo=django" alt="Django">
  <img src="https://img.shields.io/badge/React-18.2-61DAFB.svg?style=for-the-badge&logo=react" alt="React">
  <img src="https://img.shields.io/badge/Vercel-black?style=for-the-badge&logo=vercel" alt="Vercel">
  <img src="https://img.shields.io/badge/Render-46E3B7?style=for-the-badge&logo=render" alt="Render">
</p>

A robust, full-stack web application designed to streamline the hospital appointment process for patients, doctors, and administrators. This system provides a seamless user experience from registration to post-appointment management.

---

### 🚀 Live Application

*   **Frontend (React on Vercel):** **https://titikshahospitals.vercel.app/**
*   **Backend API (Django on Render):** **https://titikshahospitals.onrender.com**

---

### ✨ Core Features

The application is built with distinct workflows for each user role: Patient, Doctor, and Admin.

#### 🧑‍⚕️ For Patients
*   **Secure Authentication:** Easy registration and login using credentials. Includes a "Forgot Password" feature with OTP sent to the registered email.
*   **Doctor Discovery:** Browse a comprehensive list of available doctors and view their detailed profiles, including specializations and schedules.
*   **Effortless Appointment Booking:** Select a doctor, choose an available date and time slot, and provide a brief description of the medical problem.
*   **Automated Notifications:** Receive instant email confirmations upon successfully booking an appointment.
*   **Appointment Management:** View a personal dashboard of all upcoming and past appointments (Medical History).
*   **Cancellation Notifications:** Receive an email notification if an appointment is canceled by either the patient or the doctor.

#### 👨‍⚕️ For Doctors
*   **Secure & Vetted Registration:** Doctors can only register using a unique, one-time activation code provided by the hospital administration, ensuring only authorized personnel have access.
*   **Appointment Dashboard:** View a schedule of all upcoming appointments, including patient details and the problem description.
*   **Manage Schedule:** Cancel appointments if necessary, which automatically triggers an email notification to the respective patient.
*   **Password Recovery:** Secure "Forgot Password" functionality via OTP sent to their professional email.

#### 👑 For Admins (Backend Management)
*   **Doctor Management:** The admin is responsible for adding new doctors to the system and managing their profiles.
*   **Schedule Control:** Admins define and manage the duty timings and availability for each doctor.
*   **Activation Code Generation:** Admins generate and securely distribute the unique activation codes required for doctor registration.

---

### 🌊 Application Workflow

The primary workflow revolves around a secure and notified appointment booking process:

1.  **Booking:** A Patient logs in, selects a Doctor and Time Slot, and books an appointment.
2.  **Confirmation:** The system immediately sends a confirmation email to both the Patient and the Doctor.
3.  **Cancellation:** If either the Patient or Doctor cancels the appointment, the system sends a cancellation notification to the other party.

---

### 🛠️ Tech Stack & Architecture

This project is a monorepo with a decoupled frontend and backend.

*   **Backend:**
    *   **Framework:** Django, Django REST Framework
    *   **Language:** Python
    *   **Database:** PostgreSQL (managed by Render's free tier)
    *   **Authentication:** JWT (JSON Web Tokens)
    *   **Email Service:** Django's email backend (e.g., SendGrid/SMTP)

*   **Frontend:**
    *   **Library:** React.js
    *   **State Management:** React Context API or Redux
    *   **Styling:** CSS3, Material-UI, or custom styling
    *   **HTTP Client:** Axios

*   **Deployment:**
    *   **Backend:** **Render** (Chosen as a modern, cost-effective alternative to Heroku's retired free tier).
    *   **Frontend:** **Vercel** (Optimized for high-performance React applications).

---

### 📂 Project Structure


/
├── backend/
│ ├── appointments/ # Handles appointment logic
│ ├── authentication/ # Manages user/doctor auth & registration
│ ├── hospital/ # Main Django project settings
│ ├── manage.py
│ ├── requirements.txt # Python dependencies
│ ├── build.sh # Render build script
│ └── Procfile # (Optional for Render, good practice)
│
└── frontend/
├── public/
├── src/
│ ├── api/ # Axios instances and API calls
│ ├── components/ # Reusable React components
│ ├── pages/ # Page-level components
│ ├── App.js
│ └── ...
└── package.json # Node.js dependencies




*   **To run this project on your local machine, follow these steps.**

#### Prerequisites
*   Git
*   Python 3.9+ & Pip
*   Node.js & npm
*   A PostgreSQL database instance (local or cloud)

#### 1. Clone the Repository
```bash
git clone https://github.com/asrith2208/hospital-appointment-system.git
cd hospital-appointment-system
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
IGNORE_WHEN_COPYING_END
2. Backend Setup
Generated bash
# Navigate to the backend directory
cd backend

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`

# Install dependencies
pip install -r requirements.txt

# Create a .env file in the /backend/ root
# and add your environment variables (see example below)
cp .env.example .env

# Run database migrations
python manage.py migrate

# Start the Django development server
python manage.py runserver
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

Backend .env.example:

Generated env
# Create a file named '.env' in the /backend/ folder
SECRET_KEY='your-strong-django-secret-key'
DEBUG=True
DATABASE_URL='postgres://user:password@host:port/dbname'

# Email settings for notifications
EMAIL_BACKEND='django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST='smtp.gmail.com'
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER='your-email@gmail.com'
EMAIL_HOST_PASSWORD='your-gmail-app-password' # Use an App Password if using Gmail
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Env
IGNORE_WHEN_COPYING_END
3. Frontend Setup
Generated bash
# Navigate to the frontend directory from the root
cd frontend

# Install dependencies
npm install

# Create a .env file in the /frontend/ root
# and add your environment variables (see example below)
cp .env.example .env

# Start the React development server
npm start
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Bash
IGNORE_WHEN_COPYING_END

Frontend .env.example:

Generated env
# Create a file named '.env' in the /frontend/ folder
REACT_APP_API_BASE_URL='http://127.0.0.1:8000'
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Env
IGNORE_WHEN_COPYING_END
☁️ Deployment Guide
Deploying the Django Backend on Render

Fork this repository.

Go to Render.com and create a new "Web Service".

Connect your forked GitHub repository.

Configure the service:

Name: hospital-backend (or your choice)

Root Directory: backend

Environment: Python 3

Region: Choose a region close to you.

Build Command: pip install -r requirements.txt

Start Command: gunicorn hospital.wsgi

Add a PostgreSQL database from the Render dashboard. Render will provide a DATABASE_URL.

Go to your Web Service's "Environment" tab and add all the variables from your .env file (like SECRET_KEY, EMAIL_HOST_USER, etc.). Use the DATABASE_URL provided by Render. Set DEBUG=False for production.

Deploying the React Frontend on Vercel

Fork this repository.

Go to Vercel.com and create a "New Project".

Import your forked GitHub repository.

Vercel will auto-detect that it's a React project.

In the "Configure Project" step:

Expand the "Build & Development Settings".

Set the "Root Directory" to frontend.

Expand the "Environment Variables".

Add a variable named REACT_APP_API_BASE_URL and set its value to your live Render backend URL (e.g., https://titikshahospitals.onrender.com).

Click "Deploy".

👤 Author

Asrith
