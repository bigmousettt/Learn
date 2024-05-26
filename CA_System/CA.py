import os
import socket
import uuid
import time
import calendar
import logging
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
from peewee import *
from passlib.context import CryptContext
import user_gen_keypair

USER_INFO_PATH = "users.db"
CERT_PATH = "certificates/"
REVOKED_CERT_PATH = "revoked_certificates/"
USER_DOC_PATH = "user_documents/"
LDAP_PATH = "LDAP"

db = SqliteDatabase(USER_INFO_PATH)

class User(Model):
    user_id = CharField(unique=True)
    user_name = CharField()
    email = CharField()
    password = CharField()
    public_key = TextField()
    created_time = BigIntegerField()
    status = CharField()

    class Meta:
        database = db

HEADER = ['user_id', 'user_name', 'email', 'password', 'public_key', 'created_time', 'status']

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

logging.basicConfig(filename='ca_system.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def hash_password(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def initialize_storage():
    db.connect()
    db.create_tables([User])

    if not os.path.exists(CERT_PATH):
        os.makedirs(CERT_PATH)
    if not os.path.exists(REVOKED_CERT_PATH):
        os.makedirs(REVOKED_CERT_PATH)
    if not os.path.exists(USER_DOC_PATH):
        os.makedirs(USER_DOC_PATH)

def log_event(event):
    logging.info(event)

def save_user_info(user_name, email, password, public_key, id_document_path):
    user_id = str(uuid.uuid4())  # 生成用户ID
    created_time = calendar.timegm(time.gmtime())
    hashed_password = hash_password(password)  # 加密密码
    User.create(user_id=user_id, user_name=user_name, email=email, password=hashed_password, public_key=public_key, created_time=created_time, status="pending")
    # 保存身份证明文件路径
    id_document_storage_path = os.path.join(USER_DOC_PATH, f"{user_id}_id_document.pdf")
    os.rename(id_document_path, id_document_storage_path)
    log_event(f"User created: {user_id}, {user_name}")
    return user_id, password

def authenticate_user(user_id, password):
    try:
        user = User.get(User.user_id == user_id)
        if verify_password(password, user.password):
            return True
        else:
            return False
    except DoesNotExist:
        return False

def get_public_pem(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem

def get_local_hostname():
    return socket.gethostname()

def issue_certificate(ca_private_key, user_public_key, user_name, user_id, valid_days=365):
    cert_status, message = check_certificate_status(user_id)
    if cert_status:
        print(message)
        return None, None
    
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, user_name),])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, get_local_hostname()),])  # 使用本地计算机名称作为颁发者信息
    valid_from = datetime.utcnow()
    valid_to = valid_from + timedelta(days=valid_days)  # 自定义有效期
    builder = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
        user_public_key).serial_number(x509.random_serial_number()).not_valid_before(
        valid_from).not_valid_after(valid_to).add_extension(
        x509.KeyUsage(digital_signature=True, content_commitment=True, key_encipherment=True,
                      data_encipherment=True, key_agreement=True, key_cert_sign=True,
                      crl_sign=True, encipher_only=False, decipher_only=False),
        critical=True)

    certificate = builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256(), backend=default_backend())
    cert_file_path = os.path.join(CERT_PATH, f"{user_id}_cert.pem")
    with open(cert_file_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    log_event(f"Certificate issued: {user_id}, path: {cert_file_path}")
    return cert_file_path, certificate.serial_number


def revoke_certificate(user_id):
    cert_file_path = os.path.join(CERT_PATH, f"{user_id}_cert.pem")
    revoked_cert_file_path = os.path.join(REVOKED_CERT_PATH, f"{user_id}_revoked_cert.pem")
    if os.path.exists(cert_file_path):
        os.rename(cert_file_path, revoked_cert_file_path)
        log_event(f"Certificate for user {user_id} has been revoked.")
        User.delete().where(User.user_id == user_id).execute()
    else:
        log_event(f"Attempt to revoke non-existent certificate for user {user_id}.")

def load_public_key_from_file(file_path):
    with open(file_path, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read(), default_backend())
    return public_key

def update_ldap(cert_file_path, serial_number):
    with open(LDAP_PATH, 'a') as ldap_file:
        if serial_number != "None" and cert_file_path != "None":
            ldap_file.write(f"Certificate Serial Number: {serial_number}\n")
            ldap_file.write(f"Certificate Path: {cert_file_path}\n")

def check_certificate_status(user_id):
    cert_file_path = os.path.join(CERT_PATH, f"{user_id}_cert.pem")
    if os.path.exists(cert_file_path):
        with open(cert_file_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        now = datetime.utcnow()
        if cert.not_valid_before <= now <= cert.not_valid_after:
            return True, None
        else:
            return False, "The certificate has expired."
    else:
        return False, "No certificate found for this user."

def review_certificate_request(user_id, approve):
    user = User.get(User.user_id == user_id)
    if approve:
        user.status = "approved"
        user.save()
        log_event(f"User {user.user_id} approved.")
        return True
    else:
        user.status = "rejected"
        user.save()
        log_event(f"User {user.user_id} rejected.")
        return False

def admin_review_interface():
    pending_users = User.select().where(User.status == "pending")
    for user in pending_users:
        print(f"Reviewing user: {user.user_name}, {user.email}")
        id_document_path = os.path.join(USER_DOC_PATH, f"{user.user_id}_id_document.pdf")
        print(f"ID Document Path: {id_document_path}")
        approve = input("Approve this user? (y/n): ").strip().lower() == 'y'
        review_certificate_request(user.user_id, approve)
        if approve:
            print(f"User {user.user_name} approved.")
        else:
            print(f"User {user.user_name} rejected.")

# Main workflow
if __name__ == "__main__":
    initialize_storage()

    ca_private_key, _ = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend()), rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend()).public_key()

    print('Welcome to the CA system')
    banner = '''
    please input your choice of functions:
    1 - (User) Submit a new certificate request to RA
    2 - (RA) Admin review pending requests
    3 - (CA) Issue a certificate to User 
    4 - (CA) Revoke a certificate to User
    5 - (User) Check certificate status of User
    0 - Exit
    '''
    choice = int(input(banner))
    while choice != 0:
        if choice == 1:
            user_name = input("Enter your name: ")
            user_gen_keypair.key_pair(user_name)
            email = input("Enter your email: ")
            password = input("Enter your password: ")
            file_path = input("Enter the path to the public key file: ")
            id_document_path = input("Enter the path to your ID document: ")
            user_public_key = load_public_key_from_file(file_path)
            user_id, password = save_user_info(user_name, email, password, get_public_pem(user_public_key), id_document_path)
            print(f"Certificate request submitted successfully. Your User ID: {user_id}. Please wait for admin approval.")
        elif choice == 2:
            admin_review_interface()
        elif choice == 3:
            user_id = input("Enter user ID to issue certificate: ")
            password = input("Enter your password: ")
            if authenticate_user(user_id, password):
                user = User.get(User.user_id == user_id)
                if user.status == "approved":
                    user_public_key = serialization.load_pem_public_key(user.public_key.encode(), default_backend())
                    cert_path, serial_number = issue_certificate(ca_private_key, user_public_key, user.user_name, user.user_id)
                    print(f"Certificate issued successfully. Saved at {cert_path}")
                    update_ldap(cert_path, serial_number)
                else:
                    print("User is not approved yet.")
            else:
                print("Authentication failed.")
        elif choice == 4:
            user_id = input("Enter user ID to revoke certificate: ")
            password = input("Enter your password: ")
            if authenticate_user(user_id, password):
                revoke_certificate(user_id)
            else:
                print("Authentication failed.")
        elif choice == 5:
            user_id = input("Enter user ID to check certificate status: ")
            status, message = check_certificate_status(user_id)
            if status:
                print(f"The certificate for user {user_id} is valid.")
            else:
                print(f"Certificate status for user {user_id}: {message}")
        else:
            print("Invalid choice. Please try again.")
        choice = int(input(banner))
    print('CA system shutdown!')
