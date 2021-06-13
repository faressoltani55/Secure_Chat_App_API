from OpenSSL import crypto
import base64

from cryptography.hazmat.primitives import serialization


def get_server_key():
    with open("server_pki/.pem", "r") as pkey_file:
        pkey_text = pkey_file.read()
        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, pkey_text)
    return pkey


def generate_client_key_pair(password):
    try:
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 1024)
        with open("client_certificate/pub.pem", "wb") as public_key:
            public_key.write(crypto.dump_publickey(crypto.FILETYPE_PEM, key))
        with open("client_certificate/.pem", "wb") as private_key:
            passphrase = password
            private_key.write(
                crypto.dump_privatekey(crypto.FILETYPE_PEM, key, passphrase=bytes(passphrase, encoding='utf-8')))
        return key
    except Exception as e:
        print(e)
        return False


def get_client_certificate(path):
    with open(path, "rt") as f:
        text = f.read()
        return text


def generate_client_certificate(
        emailAddress,
        commonName,
        countryName="TN",
        localityName="Tunis",
        stateOrProvinceName="Tunis",
        organizationName="ChatServerCompany",
        organizationUnitName="ChatServerCompany",
        serialNumber=0,
        validityEndInSeconds=10 * 365 * 24 * 60 * 60,
        CERT_FILE="client_certificate/cert.pem",
        key=None):
    # can look at generated file using openssl:
    # openssl x509 -inform pem -in selfsigned.crt -noout -text
    # create a key pair
    if key is None:
        client_pub_key = generate_client_key_pair("passphrase")
    else:
        key = base64.b64decode(key)
        public_key = serialization.load_pem_public_key(key)
        client_pub_key = crypto.PKey.from_cryptography_key(public_key)
    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = countryName
    cert.get_subject().ST = stateOrProvinceName
    cert.get_subject().L = localityName
    cert.get_subject().O = organizationName
    cert.get_subject().OU = organizationUnitName
    cert.get_subject().CN = commonName
    cert.get_subject().emailAddress = emailAddress
    cert.set_serial_number(serialNumber)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(validityEndInSeconds)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(client_pub_key)
    server_pub_key = get_server_key()
    cert.sign(server_pub_key, 'sha512')
    dumped_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8")
    with open(CERT_FILE, "wt") as f:
        f.write(dumped_cert)
    return dumped_cert
