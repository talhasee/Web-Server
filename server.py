from flask import Flask, request, send_file, render_template
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
import PyPDF2
from PyPDF2 import PdfFileReader, PdfFileWriter, PdfWriter, PdfReader
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
# from cryptography.x509.oid import NameOID
from cryptography.x509.name import NameOID
from cryptography.x509 import CertificateBuilder
from datetime import datetime, timezone, timedelta
import textwrap
import requests
import os
import socket
import struct
import time
import hashlib

NTP_SERVER = "time.google.com"


app = Flask(__name__)
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/', methods=['POST'])
def get_graduate_info():    
    graduate_name = request.form['graduate_name']
    roll_number = request.form['roll_number']


    #Generate public and private key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    #Generate Degree_Certificate and Grade Card
    generate_certificate(graduate_name, roll_number, private_key)

    return f"Graduate Name: {graduate_name}, Roll Number: {roll_number}"



#-------------------1---------------------
def get_ntp_time():
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    data = b'\x1b' + 47 * b'\0'
    client.sendto(data, (NTP_SERVER, 123))
    data, address = client.recvfrom(1024)
    if data:
        response = struct.unpack('!12I', data)[10]
        response -= 2208988800
        return time.ctime(response)
    

# Define the directory where the signed documents will be stored
DOCUMENT_DIR = 'documents/'



# Generate the root certificate and key
ROOT_CERT_FILE = 'root.cert'
ROOT_KEY_FILE = 'root.key'
if not os.path.exists(ROOT_CERT_FILE) or not os.path.exists(ROOT_KEY_FILE):
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'Example University'),
    ])
    subject = issuer = name
    root_cert = CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(root_key.public_key()).serial_number(1000).not_valid_before(datetime.utcnow()).not_valid_after(datetime.utcnow() + timedelta(days=365)).sign(root_key, hashes.SHA256())
    with open(ROOT_KEY_FILE, 'wb') as f:
        f.write(root_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
    with open(ROOT_CERT_FILE, 'wb') as f:
        f.write(root_cert.public_bytes(encoding=serialization.Encoding.PEM))



def generate_certificate(name, roll_number, private_key):
    # Create a new PDF canvas with the pre-made template
    doc_name = name + ".pdf"
    pdf_canvas = canvas.Canvas(doc_name)
    pdf_canvas.setPageSize((595.27, 841.89))

    # Define the location of the text fields on the PDF
    name_x, name_y = 100, 750
    roll_number_x, roll_number_y = 100, 700
    timestamp_x, timestamp_y = 100, 650
    signature_x, signature_y = 100, 750  # <-- Change y coordinate

    # Add the graduate's information to the PDF
    pdf_canvas.drawString(name_x, name_y, f"Name: {name}")
    pdf_canvas.drawString(roll_number_x, roll_number_y, f"Roll Number: {roll_number}")

    # Add the timestamp to the PDF
    # timestamp = int(get_ntp_time())
    # timestamp_str = time.ctime(timestamp)
    timestamp_str = get_ntp_time()
    pdf_canvas.drawString(timestamp_x, timestamp_y, f"Timestamp: {timestamp_str}")

    # Hash the PDF data
    pdf_data = pdf_canvas.getpdfdata()
    pdf_hash = hashlib.sha256(pdf_data).digest()

    # Sign the PDF hash with the private key
    signature = private_key.sign(
        pdf_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Add the signature to the PDF
    signature_text = f"Signature: {signature.hex()}"
    max_width = 400  # set the maximum width of the text
    lines = textwrap.wrap(signature_text, width=50)  # split the text into lines of 50 characters
    for i, line in enumerate(lines):
        y = signature_y - i * 15  # change y coordinate for each line to simulate wrapping
        pdf_canvas.drawString(signature_x, y, line)

    # Save the PDF file
    pdf_canvas.save()




if __name__ == '__main__':
    app.run()