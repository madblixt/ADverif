import ldap
import smtplib

# Bind to the Active Directory server
ldap_conn = ldap.initialize('ldap://ad.example.com:389')
ldap_conn.set_option(ldap.OPT_REFERRALS, 0)
ldap_conn.simple_bind_s('cn=Administrator,dc=example,dc=com', 'password')

# Search for all users in the domain
result = ldap_conn.search_s('dc=example,dc=com', ldap.SCOPE_SUBTREE, 'objectCategory=person')

# Check the login history of all the users
for dn, entry in result:
    login_history = ldap_conn.search_s(dn, ldap.SCOPE_BASE, '(objectClass=*)', ['logonCount', 'lastLogonTimestamp', 'badPwdCount', 'lastBadPasswordAttempt'])[0][1]

    # Check for login attempts from unfamiliar IP addresses
    if 'dNSHostName' in entry:
        ip_addresses = entry['dNSHostName']
        if len(ip_addresses) > 1:
            # Send an alert to the administrator if the user has logged in from multiple IP addresses
            from_address = 'noreply@example.com'
            to_address = 'admin@example.com'
            subject = 'Suspicious login activity'
            body = 'User ' + entry['cn'][0] + ' has logged in from multiple IP addresses: ' + ', '.join(ip_addresses)
            message = 'Subject: {}\n\n{}'.format(subject, body)
            smtp_conn = smtplib.SMTP('smtp.example.com')
            smtp_conn.sendmail(from_address, to_address, message)

    # Check for a sudden increase in failed login attempts
    if 'badPwdCount' in login_history:
        bad_password_count = int(login_history['badPwdCount'][0])
        if bad_password_count > 5:
            # Send an alert to the administrator if the user has had more than 5 failed login attempts
            from_address = 'noreply@example.com'
            to_address = 'admin@example.com'
            subject = 'Suspicious login activity'
            body = 'User ' + entry['cn'][0] + ' has had ' + str(bad_password_count) + ' failed login attempts.'
            message = 'Subject: {}\n\n{}'.format(subject, body)
            smtp_conn = smtplib.SMTP('smtp.example.com')
            smtp_conn.sendmail(from_address, to_address, message)

# Disconnect from the server
ldap_conn.unbind_s()
