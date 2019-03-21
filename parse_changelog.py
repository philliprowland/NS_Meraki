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

def main(json_changelog):

    list_logs = [] # Instantiate the list to hold log entries

    logging.debug("Change Log Length: {0}".format(len(json_changelog)))

    # Epoch time at time lapse indicated
    d_timelapse = int(time.time()) - i_timelapse

    # Iterate through each org
    for org_entry in json_changelog:
        logging.debug("{0} has {1} Entries in it's change log".format(org_entry['orgID'], len(org_entry['changes'])))

        # Iterate through each change log entry in the current org
        for log_entry in org_entry['changes']:
            # Skip this entry if it's an API call and we have been instructed to show web only
            if b_webonly and log_entry['category'] == 'via API':
                continue
            
            # Skip this entry if it occured before time lapse
            if i_timelapse != 0 and log_entry['time'] < d_timelapse:
                continue

            list_entry = [log_entry['time'],org_entry['orgName'],log_entry['admin_name'],log_entry['network_name'],\
                log_entry['category'],log_entry['old_text'],log_entry['new_text']]
            list_logs.append(list_entry)
    
    list_logs.sort()

    list_logtext = []
    for log in list_logs:
        s_utc = datetime.datetime.utcfromtimestamp(log[0])
        list_logtext.append("{0}: {1} {3} - {2} changed {4} from {5} to {6}".format(s_utc,log[1],log[2],log[3],log[4],log[5],log[6]))

    return list_logtext

def usage():
    print('parse_changelog.py -i <filename> [options]')
    print(' -h               : Print this usage message')
    print(' -i <filename>    : Import <filename> and parse out changes')
    print(' -o <filename>    : The output file to write json results to')
    print(' -w               : Only include web based logs')
    print(' -t <# seconds>   : Only include logs after <# seconds> in the past (604800 = 1 Week)')

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
        elif opt == '-o':  # Output file for parsed changes
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

    logging.debug("A total of {0} change logs read from json".format(l_results.count))

    try:
        if len(str_output_file) <=0:
            for s_log in l_results:
                print(s_log)
        else:
            with open(str_output_file, "w") as f:
                for s_log in l_results:
                    f.write(s_log + "\n")
    except Exception as e:
        str_err = "Error printing Change Log results: "
        logging.fatal("{0}{1}{2}{3}\n{4}".format(
            R, str_err, str(e), W, traceback.format_tb(e.__traceback__)
        ))
        logging.shutdown()
        sys.exit(2)

    logging.shutdown()