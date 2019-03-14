#!/usr/bin/python

import sys, getopt, logging, json, traceback, datetime, time, os
from operator import itemgetter

# Define Console Color Constants
W = '\033[0m'  # white (normal)
R = '\033[91m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[94m'  # blue
P = '\033[95m'  # purple
Y = '\033[93m'  # yellow

def main(json_events):

    list_logs = [] # Instantiate the list to hold log entries

    logging.debug("Events Log Length: {0}".format(len(json_events)))

    # Epoch time at time lapse indicated
    d_timelapse = int(time.time()) - i_timelapse

    # Iterate through each org
    for org_entry in json_events:
        try :
            #logging.debug(org_entry['securityEvents'])
            securityEvents = json.loads(org_entry['securityEvents'])
            logging.debug("{0} has {1} Entries in it's change log".format(org_entry['orgName'], securityEvents['total_events']))

            # Skip this entry if it's there aren't any events
            if org_entry['securityEvents'] == 0:
                continue
        except Exception as e:
            logging.error(R + "Error parsing Organization " + org_entry['orgName'] + W)
            logging.debug("{0}Error parsing Organization: {1}{2}\n{3}".format(
                R,W,str(e), traceback.format_tb(e.__traceback__)))
            logging.debug(str(org_entry))
            continue

        # Iterate through each change log entry in the current org
        for log_entry in securityEvents['top_threats']:
            try:
                if 'msg' in log_entry['threat']:
                    list_entry = [org_entry['orgName'],log_entry['threat']['msg'],log_entry['threat']['priority'],\
                        log_entry['occurrences']]
                else:
                    list_entry = [org_entry['orgName'],log_entry['threat']['name'],log_entry['threat']['disposition'],\
                        log_entry['occurrences']]
                list_logs.append(list_entry)
            except Exception as e:
                logging.error(R + "Error parsing Threat" + W)
                logging.debug("{0}Error parsing Threat: {1}{2}\n{3}".format(
                    R,W,str(e), traceback.format_tb(e.__traceback__)))
                logging.debug(str(log_entry))
                continue
        
    list_logs.sort()

    list_logtext = []
    for log in list_logs:
        try:
            C = R
            write = True
            if type(log[2]) is int:
                if log[2] < 
                C = R if (log[2] >= 3) else G
                write = True if (log)
            list_logtext.append("{4}{0}: {3} occurrences of {1} - Priority {2} {5}".format(log[0],log[1],log[2],log[3],C,W))
        except Exception as e:
            logging.error(R + "Error printing event: " + log[0] + " - " + log[1] + W)
            logging.error("{0}Error printing event: {1}{2}\n{3}".format(
                R,W,str(e), traceback.format_tb(e.__traceback__)
            ))
            continue

    return list_logtext

def usage():
    print('parse_changelog.py -i <filename> [options]')
    print(' -h               : Print this usage message')
    print(' -i <filename>    : Import <filename> and parse out changes')
    print(' -o <filename>    : The output file to write json results to')
    print(' -w               : Only include web based logs')
    print(' -t <# seconds>   : Only include logs after <# seconds> in the past (604800 = 1 Week)')
    print(' -l <# level>     : Only include priority events greater than this')

if __name__ == "__main__":

    global str_date, b_webonly, i_timelapse

    str_input_file = str_output_file = ''
    # TODO Tab complete filenames

    #   Get command line arguments and parse for options
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hi:o:wt:', ['debug='])
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        sys.exit(2)

    log_level = logging.WARNING
    b_webonly = False
    i_timelapse = 0

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
        elif opt == '-o':  # Output file for parsed events
            str_output_file = arg
        elif opt == '-i':  # Input file to read
            str_input_file = arg
        elif opt == '-w':  # Set Web Only to True
            b_webonly = True
        elif opt == '-t':  # Set time-lapse argument for filtering to recent logs only
            i_timelapse = int(arg)
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

    # Get the json change file
    try:
        logging.info("{0}Loading JSON Change Log file: {1}{2}".format(P,W,str_input_file))
        json_changelog = json.load(open(str_input_file, "r"))
        
    except Exception as e:
        str_err = "Error reading JSON Change Log file: "
        logging.fatal("{0}{1}{2}{3}\n{4}".format(
            R, str_err, str(e), W, traceback.format_tb(e.__traceback__)
        ))
        logging.shutdown()
        sys.exit(2)

    l_results = main(json_changelog)

    if len(str_output_file) <=0:
        for s_log in l_results:
            print(s_log)
    else:
        with open(str_output_file, "w") as f:
            for s_log in l_results:
                f.write(s_log + "\n")

    logging.shutdown()