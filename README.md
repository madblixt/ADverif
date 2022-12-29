# ADverif

Copy the script to a machine that has the necessary libraries (ldap and smtplib) installed.

Modify the script to specify the hostname and port of your Active Directory server, as well as the bind DN and password of an administrator account that has permissions to search the directory.

If you want to send email alerts when suspicious activity is detected, you will also need to modify the script to specify the hostname and port of your SMTP server and the email addresses of the administrator and the sender.

Run the script using a command like python monitor_user_accounts.py. The script will connect to the Active Directory server, search for all users in the domain, and check their login history. If any suspicious activity is detected, the script will send an email alert to the administrator.

You can schedule the script to run regularly (e.g. once a day) using a tool like cron on Unix-like systems or the Task Scheduler on Windows. This will allow the script to mo
