from OpenSSL import crypto


def generate_server_key_pair():
    try:
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 1024)
        with open("server_pki/pub.pem", "wb") as public_key:
            public_key.write(crypto.dump_publickey(crypto.FILETYPE_PEM, key))
        with open("server_pki/.pem", "wb") as private_key:
            passphrase = input("Passphrase: ")
            private_key.write(
                crypto.dump_privatekey(crypto.FILETYPE_PEM, key, passphrase=bytes(passphrase, encoding='utf-8')))
        return key
    except Exception as e:
        print(e)
        return False


def generate_server_certificate(
        emailAddress="chat_server@gmail.com",
        commonName="chat_server",
        countryName="TN",
        localityName="Tunis",
        stateOrProvinceName="Tunis",
        organizationName="ChatServerCompany",
        organizationUnitName="ChatServerCompany",
        serialNumber=0,
        validityEndInSeconds=10 * 365 * 24 * 60 * 60,
        CERT_FILE="server_pki/cert.pem"):
    # can look at generated file using openssl:
    # openssl x509 -inform pem -in selfsigned.crt -noout -text
    # create a key pair
    k = generate_server_key_pair()
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
    cert.set_pubkey(k)
    cert.sign(k, 'sha512')
    with open(CERT_FILE, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
