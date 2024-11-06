# Example Web Application

This is a web application built with Flask that provides user registration, login, and email verification functionalities. It uses MySQL for data storage and JWT for session management.

## Features

- User Registration
- User Login
- Email Verification
- Secure Password Hashing
- JWT-based Authentication
- Cloudflare Turnstile

## Prerequisites

- Python 3.x
- MySQL Server
- Required Python packages (listed in `requirements.txt`)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/yourproject.git
   cd yourproject
   ```

2. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up the MySQL database using the provided schema.

4. Configure the application by editing `config.json` with your MySQL and email server details.

## Running the Application

1. Start the Flask application:
   ```bash
   python app.py
   ```

2. Open your web browser and go to `http://localhost:4321` to access the application.

## Usage

- Register a new account using the registration form.
- Verify your email by clicking the link sent to your email address.
- Log in using your username or email and password.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
