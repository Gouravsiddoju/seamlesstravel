Seamless Travel Digital Identity PlatformThis is a Flask-based web application that serves as a proof-of-concept for a seamless travel system. It allows users to create a digital identity by uploading their travel documents (Passport, Aadhaar, Driving License) and a boarding pass. The system generates a single, secure QR code that can be scanned by authorized personnel to validate the traveler's identity and flight information.FeaturesUser Authentication: Secure user registration and login system with password hashing (Werkzeug).Document Management: Users can manually add details for their Passport, Aadhaar Card, and Driving License.Sequential Onboarding: A guided, step-by-step process for users to complete their profile.Identity Verification (Simulation): A workflow for users to submit documents for identity verification.Secure QR Code Generation: Generates a unique, server-side QR code for each user that contains a secure link, not sensitive data.API-Protected Validation: A secure /validate endpoint that requires an API key, preventing unauthorized access to passenger data.Project Structure/seamless-travel-app/
|
|-- /instance/
|   |-- travel.db           # The SQLite database file (auto-generated)
|
|-- /templates/
|   |-- base.html           # Base template with common styles
|   |-- login.html          # User login page
|   |-- register.html       # User registration page
|   |-- dashboard.html      # User's main dashboard
|   |-- add_passport.html   # Form for manual passport entry
|   |-- add_aadhaar.html    # Form for Aadhaar card entry
|   |-- add_driving_license.html # Form for Driving License entry
|   |-- add_boarding_pass.html # Form for boarding pass entry
|   |-- verify_identity.html  # Page for simulated ID verification
|   |-- validate.html       # Page for displaying validated user data
|
|-- app.py                  # Main Flask application file
|-- requirements.txt        # List of Python dependencies
|-- README.md               # This file
PrerequisitesBefore you begin, ensure you have the following software installed on your system.1. PythonThis project requires Python 3.8 or newer.To check if you have it: Open your terminal or command prompt and run python --version.To install it: Download it from the official python.org website.2. Tesseract-OCR EngineThis is a critical dependency for the identity verification feature. The Python library pytesseract is just a wrapper and needs this engine to be installed on your computer.Windows:Download the installer from the Tesseract at UB Mannheim page.Run the installer. Important: Make sure to check the box to add Tesseract to your system's PATH.After installation, restart your computer.macOS:Install via Homebrew: brew install tesseractLinux (Debian/Ubuntu):Run: sudo apt-get update && sudo apt-get install tesseract-ocrSetup & InstallationFollow these steps to get the application running on your local machine.1. Clone the Repositorygit clone <your-repository-url>
cd seamless-travel-app
2. Create a Virtual Environment (Recommended)It's best practice to run the project in a virtual environment.# Create the environment
python -m venv venv

# Activate it
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
3. Install Required Python PackagesThe requirements.txt file lists all the necessary packages.pip install -r requirements.txt
4. Run the ApplicationOnce all the packages are installed, you can start the server.python app.py
The server will start, and you will see output indicating it is running on http://0.0.0.0:5000. The first time you run it, a folder named instance will be created containing the travel.db database file.How to Use the ApplicationAccess the App: Open your web browser and navigate to http://127.0.0.1:5000.Register: Create a new user account.Log In: Log in with your new credentials.Follow Onboarding: The dashboard will guide you through the process:Add your Passport details.Add a second ID (Aadhaar or Driving License).Verify your identity (this is a simulation).Add your boarding pass details.Get QR Code: Once your profile is complete, your unique, secure QR code will be displayed.Test Validation:Scan the QR code with your phone. It will give you a URL like http://<YOUR_IP>:5000/validate/<token>.To test the secure endpoint, you must manually add the API key to the URL: http://<YOUR_IP>:5000/validate/<token>?api_key=Techoptima.Future EnhancementsThis prototype can be extended with the following features:Real Identity Verification: Replace the simulation with a real verification service like Persona or a library like CivicIQ-Verifier with DigiLocker integration.Real OCR: Implement the OCR logic to automatically extract data from uploaded documents.Secure API Authentication: Change the API key check from a URL parameter to a more secure HTTP Authorization header.Agent Interaction: Add a feature for an agent to "Mark as Boarded," which would update the boarding pass status in the database.Profile Pictures: Allow users to upload a profile picture to be displayed on the validation page for a quick visual check.ContributingContributions are welcome! Please feel free to submit a pull request or open an issue to discuss potential changes or additions.LicenseThis project is licensed under the MIT License. See the LICENSE file for details.
