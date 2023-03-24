import ldap
import smtplib


def connect_ldap():
    try:
        ldap_conn = ldap.initialize('ldap://ad.example.com:389')
        ldap_conn.set_option(ldap.OPT_REFERRALS, 0)
        ldap_conn.simple_bind_s('cn=Administrator,dc=example,dc=com', 'password')
        return ldap_conn
    except ldap.LDAPError as e:
        print("Erreur de connexion LDAP : " + str(e))
        exit()


def search_users(ldap_conn):
    try:
        return ldap_conn.search_s('dc=example,dc=com', ldap.SCOPE_SUBTREE, 'objectCategory=person')
    except ldap.LDAPError as e:
        print("Erreur de recherche LDAP : " + str(e))
        exit()


def get_login_history(ldap_conn, dn):
    try:
        return ldap_conn.search_s(dn, ldap.SCOPE_BASE, '(objectClass=*)', ['logonCount', 'lastLogonTimestamp', 'badPwdCount', 'lastBadPasswordAttempt'])[0][1]
    except ldap.LDAPError as e:
        print("Erreur de recherche LDAP : " + str(e))
        return None


def send_email(subject, body):
    try:
        from_address = 'noreply@example.com'
        to_address = 'admin@example.com'
        message = f'Subject: {subject}\n\n{body}'
        smtp_conn = smtplib.SMTP('smtp.example.com')
        smtp_conn.sendmail(from_address, to_address, message)
    except smtplib.SMTPException as e:
        print("Erreur d'envoi d'e-mail : " + str(e))


ldap_conn = connect_ldap()
users = search_users(ldap_conn)

for dn, entry in users:
    login_history = get_login_history(ldap_conn, dn)
    if login_history is None:
        continue

    if 'dNSHostName' in entry:
        ip_addresses = entry['dNSHostName']
        if len(ip_addresses) > 1:
            subject = 'Suspicious login activity'
            body = f"User {entry['cn'][0]} has logged in from multiple IP addresses: {', '.join(ip_addresses)}"
            send_email(subject, body)

    if 'badPwdCount' in login_history:
        bad_password_count = int(login_history['badPwdCount'][0])
        if bad_password_count > 5:
            subject = 'Suspicious login activity'
            body = f"User {entry['cn'][0]} has had {bad_password_count} failed login attempts."
            send_email(subject, body)

ldap_conn.unbind_s()
