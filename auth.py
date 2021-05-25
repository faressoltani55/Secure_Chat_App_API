from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.core.exceptions import LDAPException, LDAPBindError
from flask import request, session, Response, send_file

# ldap server hostname and port
from certificates import generate_client_certificate, get_client_certificate

ldap_server = f"ldap://localhost:10389"

connection = None


# sample user
def sample_user():
    user = {}
    user["username"] = "test"
    user["password"] = "test"
    user["firstname"] = "test"
    user["lastname"] = "test"
    return user


# dn
root_dn = "dc=example,dc=org"


def root_connect():
    ldap_username = "admin"
    ldap_password = "secret"
    return connect(ldap_username,ldap_password)


def connect(username, password):
    try:
        user = f'uid={username}, ou=system'
        server = Server(ldap_server, get_info=ALL)
        connection = Connection(server,
                                user=user,
                                password=password)
        print(connection.bind())
        return connection
    except LDAPBindError as e:
        connection = e
        return connection


def get_ldap_users():
    # Provide a search base to search for.
    search_base = 'ou=users,ou=system'
    # provide a uidNumber to search for. '*" to fetch all users/groups
    search_filter = '(objectClass=inetOrgPerson)'

    # Establish connection to the server
    ldap_conn = root_connect()
    try:
        # only the attributes specified will be returned
        ldap_conn.search(search_base=search_base,
                         search_filter=search_filter,
                         search_scope=SUBTREE,
                         attributes=['cn', 'sn'])
        # search will not return any values.
        # the entries method in connection object returns the results
        results = ldap_conn.entries
        print(results)
    except LDAPException as e:
        results = str(e)
        print(results)
    return results


def get_ldap_user_certificate(username):
    # Provide a search base to search for.
    search_base = 'ou=users,ou=system'
    # provide a uidNumber to search for. '*" to fetch all users/groups
    search_filter = '(&(objectClass=inetOrgPerson)(cn=' + username + '))'

    # Establish connection to the server
    ldap_conn = root_connect()
    try:
        # only the attributes specified will be returned
        ldap_conn.search(search_base=search_base,
                         search_filter=search_filter,
                         search_scope=SUBTREE,
                         attributes=['userCertificate'])
        # the entries method in connection object returns the results
        results = ldap_conn.entries[0]['userCertificate'][0].decode("utf-8")
    except LDAPException as e:
        results = str(e)
        print(results)
    return results


def create_user(user, ldap_user):
    ldap_user["cn"] = user["username"]
    ldap_user["sn"] = user["username"]
    ldap_user["userPassword"] = user["password"]
    ldap_user["displayName"] = user["firstname"]
    ldap_user["givenName"] = user["lastname"]
    ldap_user["mail"] = user["email"]
    ldap_user["uid"] = user["cin"]
    return ldap_user


def subscribe(user):
    # sample attributes
    ldap_user = {}
    object_class = ['inetOrgPerson', 'organizationalPerson', 'person', 'top']
    ldap_user["objectClass"] = object_class
    ldap_attr = create_user(user, ldap_user)
    generate_client_certificate(emailAddress= ldap_user["mail"], commonName=ldap_user['cn'])
    ldap_user["userCertificate"] = get_client_certificate("client_certificate/cert.pem")
    # Bind connection to LDAP server
    ldap_conn = root_connect()
    user_dn = f'cn={ldap_attr["cn"]},ou=users,ou=system'
    try:
        # object class for a user is inetOrgPerson
        ldap_conn.add(dn=user_dn,
                      attributes=ldap_attr)
        print(ldap_conn.result)
    except LDAPException as e:
        response = e
        print(e)
    return ldap_conn.result


def sign_in(username, password):
    try:
        connection = connect(username, password)
        return "Success"
    except LDAPException as e:
        return "Authentication failed : " + str(e)
    except LDAPBindError as e:
        return "Authentication failed : " + str(e)
    except Exception as e:
        return "Error : " + str(e)