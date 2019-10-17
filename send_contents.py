import smtplib, logging, sys, getopt, keyring, traceback
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Define Console Color Constants
W = '\033[0m'  # white (normal)
R = '\033[91m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[94m'  # blue
P = '\033[95m'  # purple
Y = '\033[93m'  # yellow

def main(str_file, str_login, str_email, str_subject):
    str_contents = ''
    password = keyring.get_password('O365', str_login)
    if password is None:
        print("No password exists for the user " + str_login)
        sys.exit(0)

    # Get the file contents
    try:
        logging.info("{0}Loading file contents: {1}{2}".format(P,W,str_input_file))
        with open(str_input_file, "r") as file_read:
            str_contents = file_read.read()
        
    except Exception as e:
        str_err = "Error reading file: "
        logging.fatal("{0}{1}{2}{3}\n{4}".format(
            R, str_err, str(e), W, traceback.format_tb(e.__traceback__)
        ))
        logging.shutdown()
        return False

    msg = MIMEMultipart()
    msg['From'] = str_login
    msg['To'] = str_email
    msg['Subject'] = str_subject
    msg.attach(MIMEText(str_contents, 'plain'))
    logging.debug("{0}Message: {1}{2}".format(P,W,msg))
    
    try:
        mailserver = smtplib.SMTP('smtp.office365.com',587)
        mailserver.ehlo()
        mailserver.starttls()
        mailserver.login(str_login, password)
        mailserver.send_message(msg)
        mailserver.close()
    except Exception as e:
        str_err = "Error sending message: "
        logging.fatal("{0}{1}{2}{3}\n{4}".format(
            R, str_err, str(e), W, traceback.format_tb(e.__traceback__)
        ))
        logging.shutdown()
        return False
    return True

def usage():
    print('send_contents.py -i <filename> [options]')
    print(' -h               : Print this usage message')
    print(' -i <filename>    : Read <filename> put contents in the body')
    print(' -r <email>       : The email address to send file contents to')
    print(' -e <email>       : The email of the Office 365 account to send from')
    print(' -s <subject line>: The subject for the email')

if __name__ == "__main__":

    str_input_file = str_email_address = ''

    #   Get command line arguments and parse for options
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hi:r:e:s:', ['debug='])
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        sys.exit(2)

    log_level = logging.WARNING

    for opt, arg in opts:
        if opt == '-h':  # Print usage menu
            usage()
            sys.exit()
        elif opt == '--debug':  # Set debugging level
            log_level = getattr(logging, arg.upper(), None)
            if not isinstance(log_level, int):
                print(R + "Invalid Logging Level, please use DEBUG, INFO, WARNING, ERROR, CRITICAL or FATAL" + W)
                usage()
                sys.exit(2)
        elif opt == '-r':  # Output file for parsed changes
            str_email_address = arg
        elif opt == '-i':  # Input file to read
            str_input_file = arg
        elif opt == '-e':  # O365 Account to login with
            str_login = arg
        elif opt == '-s':  # The Subject line to use
            str_subject = arg
        else:
            assert False, "unhandled option"

    #   Setup Logging
    logging.basicConfig(level=log_level)

    #   Make sure an input file was entered
    if len(str_input_file) <= 0:
        logging.error("{0}A json file must be specified using -i{1}".format(R,W))
        usage()
        logging.shutdown()
        sys.exit(2)

    # Try to email 3 times
    count = 0
    success = False
    while success == False:
        count += 1
        if count > 3:
            break
        success = main(str_input_file, str_login, str_email_address, str_subject)

    logging.shutdown()