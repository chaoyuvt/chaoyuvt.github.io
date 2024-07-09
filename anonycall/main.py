from flask import Flask, jsonify
import time
import csv
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import datetime

app = Flask(__name__)

# generate from your openssl
cert_path = "server.crt"
key_path = "server.key"

def load_certificate(cert_path):
    with open(cert_path, "rb") as cert_file:
        cert_data = cert_file.read()
    return x509.load_pem_x509_certificate(cert_data, default_backend())


def load_private_key(key_path):
    with open(key_path, "rb") as key_file:
        key_data = key_file.read()
    return serialization.load_pem_private_key(key_data, password=None, backend=default_backend())


def check_modulus(cert, key):
    cert_public_key = cert.public_key()
    if isinstance(cert_public_key, rsa.RSAPublicKey):
        cert_modulus = cert_public_key.public_numbers().n
    else:
        raise ValueError("The certificate does not contain an RSA public key")

    if isinstance(key, rsa.RSAPrivateKey):
        key_modulus = key.private_numbers().public_numbers.n
    else:
        raise ValueError("The private key is not an RSA key")

    return cert_modulus == key_modulus


def check_validity(cert):
    current_time = datetime.datetime.utcnow()
    return cert.not_valid_before <= current_time <= cert.not_valid_after


def verify_certificate(cert_path, key_path):
    cert = load_certificate(cert_path)
    key = load_private_key(key_path)

    if not check_modulus(cert, key):
        return False

    if not check_validity(cert):
        return False

    return True


def read_sip_uri():
    # Open the CSV file
    with open('SIP_URI.csv', mode='r') as file:
        csv_reader = csv.reader(file)

        # Read the SIP URI
        for i, row in enumerate(csv_reader):
            return row[0]  # Return the item at column 1


@app.route('/message', methods=['GET'])
def get_message():
    start_time = time.time()
    if verify_certificate(cert_path, key_path):

        sip_uri_data = read_sip_uri()
        end_time = time.time()
        execution_time = (end_time - start_time) * 1000
        execution_time = format(execution_time, '.4f')  # Keep only two decimal places
        # return jsonify({"SIP URI": sip_uri_data, "Verification Time(ms)": execution_time})
        return jsonify({"SIP URI": sip_uri_data, "Verification Time(ms)": execution_time})
    else:
        end_time = time.time()
        execution_time = (end_time - start_time) * 1000
        execution_time = format(execution_time, '.4f')  # Keep only two decimal places
        return jsonify({"Certification invalid, execution_time(ms)": execution_time})



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
