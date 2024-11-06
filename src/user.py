
from hashlib import sha512
import mysql.connector
from mysql.connector import errors
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import smtplib
from string import Template
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def password2hash(password):
    return sha512(password.encode('utf-8')).hexdigest()

def register(username, email, password, config):
    username = username.lower()
    email = email.lower()
    display_name = username
    hashed_password = password2hash(password)
    connection = mysql.connector.connect(host=config["mysql"]["host"], port=config["mysql"]["port"], user=config["mysql"]["user"], password=config["mysql"]["password"])
    cursor = connection.cursor()
    add_user_query = """
    INSERT INTO example.Users (username, displayname, email, password, emailVerified)
    VALUES (%s, %s, %s, %s, %s);
    """
    try:
        cursor.execute(add_user_query, (username, display_name, email, hashed_password, 0))
    except errors.IntegrityError as e:
        return False
    connection.commit()
    connection.close()
    return True

def login(user_or_password, password, config):
    user_or_password = user_or_password.lower()
    hashed_password = password2hash(password)
    connection = mysql.connector.connect(host=config["mysql"]["host"], port=config["mysql"]["port"], user=config["mysql"]["user"], password=config["mysql"]["password"])
    cursor = connection.cursor()
    check_user_query = """
    SELECT username FROM example.Users
    WHERE (username=%s OR email=%s) AND password=%s;
    """
    cursor.execute(check_user_query, (user_or_password, user_or_password, hashed_password))
    user = cursor.fetchone()
    if not user:
        connection.close()
        return False, "Wrong email or password"
    check_user_query = """
        SELECT username FROM example.Users
        WHERE (username=%s OR email=%s) AND password=%s AND emailVerified=1;
        """
    cursor.execute(check_user_query, (user_or_password, user_or_password, hashed_password))
    user = cursor.fetchone()
    if not user:
        connection.close()
        return False, "Email not verified"
    connection.close()
    return True, "Success"

def email_send_verification(username, config, email):
    key = base64.urlsafe_b64decode(config['auth']['email']['token_key'])
    iv = base64.urlsafe_b64decode(config['auth']['email']['token_iv'])
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(username.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    token = base64.urlsafe_b64encode(ciphertext).decode()
    with open('templates\\email_template.html', 'r') as template_file:
        email_template_content = Template(template_file.read())
    template_values = {'username': username.capitalize(), 'url': f'https://example.net/verify?token={token}'}
    msg = MIMEMultipart()
    msg['From'] = 'no-reply@example.net'
    msg['To'] = email
    msg['Subject'] = 'Example Account Verification'
    message = email_template_content.substitute(template_values)
    msg.attach(MIMEText(message, 'html'))
    mailserver = smtplib.SMTP('localhost', config['auth']['email']['port'])
    mailserver.login(config['auth']['email']['user'], config['auth']['email']['password'])
    mailserver.sendmail('iloveshell@proton.me', email, msg.as_string())
    mailserver.quit()

def email_check_token(ciphertext_base64, config):
    key = base64.urlsafe_b64decode(config['auth']['email']['token_key'])
    iv = base64.urlsafe_b64decode(config['auth']['email']['token_iv'])
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        ciphertext_decoded = base64.urlsafe_b64decode(ciphertext_base64)
        decrypted_padded = decryptor.update(ciphertext_decoded) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_text = unpadder.update(decrypted_padded) + unpadder.finalize()
    except:
        return False
    username = decrypted_text.decode()
    connection = mysql.connector.connect(host=config["mysql"]["host"], port=config["mysql"]["port"], user=config["mysql"]["user"], password=config["mysql"]["password"])
    cursor = connection.cursor()
    verify_query = "UPDATE example.Users SET emailVerified = %s WHERE username = %s"
    cursor.execute(verify_query, (1, username))
    connection.commit()
    if cursor.rowcount == 1:
        connection.close()
        return True
    connection.close()
    return False
