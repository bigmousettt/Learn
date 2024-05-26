from cryptography import x509
from cryptography.hazmat.backends import default_backend

def print_certificate_details(cert_file_path):
    with open(cert_file_path, "rb") as f:
        cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        print("Certificate Subject:")
        print(cert.subject)
        print("\nCertificate Issuer:")
        print(cert.issuer)
        print("\nCertificate Validity Period:")
        print(f"Not Before: {cert.not_valid_before}")
        print(f"Not After: {cert.not_valid_after}")
        print("\nCertificate Serial Number:")
        print(cert.serial_number)
        print("\nCertificate Public Key:")
        print(cert.public_key())

# Example usage:
cert_file_path = input("请输入数字证书路径：")#"certificates/your_certificate.pem"  # 指定证书文件路径
print_certificate_details(cert_file_path)
