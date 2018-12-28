#!/usr/bin/python

import sys, getopt, keyring, requests, logging, json, traceback, datetime, time, os
from operator import itemgetter
import meraki_extension
from meraki import meraki
from bs4 import BeautifulSoup

# Define Console Color Constants
W = '\033[0m'  # white (normal)
R = '\033[91m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[94m'  # blue
P = '\033[95m'  # purple
Y = '\033[93m'  # yellow

# TODO: IP Spoofing protection (Firewall)
# TODO: Per Network, alert settings via JSON file
# TODO: Modify Ping IP Addresses on Firewall Page
# TODO: Parse firmware updates and Alert if out of compliance
# TODO: Whitelisting Report
# TODO: SSID Lists & Export for Review
# TODO: SAML Roles
# TODO: https://n159.meraki.com/o/iE011bFc/manage/organization/change_log 

def main(username, actions):

    # Accept Invitations, Enable API and do all Org related actions
    org_lics = process_orgs(username, actions)
    logging.info(W + str(org_lics))
    logging.debug("{0}Return Value: {1}{2}".format(P, W, str(org_lics)))

    # Run all of the API based calls
    if 'a' in actions or 'g' in actions:
        apikey = keyring.get_password('merakiapi', username)
        orgs = meraki.myorgaccess(apikey, True)
        logging.debug("{0}The Organization List: {1}{2}".format(P, str(orgs), W))

        if orgs is None:
            logging.critical("The username specified does not return any Orgs")
            sys.exit(2)

        for org in orgs:
            #   TODO: Make Threading
            print(G + "Processing API Calls for " + org['name'] + W)
            process_org_api(apikey, org)

def process_org_api(apikey, org):
    # TODO: Can I dynamically add to the org dictionary of each element

    # Add administrators if requested
    if 'a' in actions:
        logging.info(B + "Validating Administrators for " + org['name'] + ":" + W)

        grant_org_admin(apikey, org)

    # Validate and adjust Network Alerts
    if 'g' in actions:
        try:
            networks = meraki.getnetworklist(apikey, org['id'], None, True)
            logging.debug(P + "API Network List: " + W + str(networks))

            for network in networks:
                needs_update = False

                alerts = meraki_extension.getnetworkalerts(apikey, network['id'], True)
                logging.debug("{3}{0}Alerts: {1}{2}".format(P, W, str(alerts),network['id']))

                # Dump JSON alert data to a file
                json_file = "json/AlertSettings/{0}_{1}_{2}_{3}.json".format(
                    str_date, network['organizationId'],network['id'],network['name']
                )
                os.makedirs(os.path.dirname(json_file), exist_ok=True)
                json.dump(alerts, open(json_file, "w"))

                # Stop email all Network Admins
                if alerts['defaultDestinations']['allAdmins'] is True:
                    logging.debug("{0}Found Default Destinations:{1}{2}".format(P,alerts['defaultDestinations'],W))
                    needs_update = True
                    alerts['defaultDestinations']['allAdmins'] = False

                    # Add alerts email the Default Email list
                    if 'alerts@netsmartai.com' not in alerts['defaultDestinations']['emails']:
                        needs_update = True
                        alerts['defaultDestinations']['emails'].append('alerts@netsmartai.com')

                    # TODO: Remove all user admin accounts
                    # Remove help desk email in favor of the alerts (NOC) email
                    if 'help@netsmart.support' in alerts['defaultDestinations']['emails']:
                        needs_update = True
                        alerts['defaultDestinations']['emails'].remove('help@netsmart.support')

                # Fix the destinations list for any alert set to All Admins
                for alert in alerts['alerts']:
                    if alert['enabled'] is False:
                        continue

                    if alert['alertDestinations']['allAdmins'] is True:
                        logging.debug("Found alert:{0}".format(str(alert)))
                        needs_update = True

                        alert['alertDestinations']['allAdmins'] = False
                        if 'alerts@netsmartai.com' not in alerts['defaultDestinations']['emails']:
                            alert['alertDestinations']['emails'].append('alerts@netsmartai.com')
                        # TODO: Remove all netsmart user admin accounts
                        if 'help@netsmart.support' in alerts['defaultDestinations']['emails']:
                            alert['alertDestinations']['emails'].remove('help@netsmart.support')

                if needs_update:
                    logging.info("{0}Updating Alert Settings: {1}{2}".format(B, W, str(alerts)))
                    resp = meraki_extension.updatenetworkalert(apikey, network['id'], alerts, True)
                    logging.info("{0}New Alert Settings: {1}{2}".format(B, resp, W))

        except (KeyboardInterrupt, SystemExit):
            sys.exit()
        except Exception as e:
            str_err = "Error processing network alert settings: "
            logging.error("{0}{1}{2}{3}\n{4}".format(
                R, str_err, str(e), W, traceback.format_tb(e.__traceback__)
            ))
            

        # TODO: getlicensestate(apikey, org['id'])
        # TODO:

def grant_org_admin(apikey, org):
    #   Get Admin list for Org from Meraki and serialize to a file
    try:
        org_admins = meraki.getorgadmins(apikey, org['id'], True)
        logging.debug("{0}Org Admin List:{1}{2}".format(P, W, org_admins))

        str_json = "json/Admins/{0}_{1}.json".format(str_date, org['name'])
        json.dump(org_admins, open(str_json, "w"))
    except (KeyboardInterrupt, SystemExit):
        sys.exit()
    except Exception as e:
        str_err = "Error getting org admins: "
        logging.error("{0}{1}{2}{3}\n{4}".format(
            R, str_err, str(e), W, traceback.format_tb(e.__traceback__)
        ))

    #   Iterate through Intended Admins and get the appropriate Org's Admin List
    try:
        json_org_admins = None
        for admin_org in json_admins:
            #   If the org is specified, or is default. This uses the first list found
            if admin_org['id'] == org['id'] or admin_org['id'] == "0":
                json_org_admins = admin_org['admins']
                break

        if json_org_admins is None:
            logging.warning("{0}No Admin specifications was found for {1}".format(O, org['name'])) 
            return
    except (KeyboardInterrupt, SystemExit):
        sys.exit()
    except Exception as e:
        str_err = "Error processing this Organization: "
        logging.error("{0}{1}{2}: {3}{4}\n{5}".format(
            R, str_err, org['name'], str(e), W, traceback.format_tb(e.__traceback__)
        ))
        return

    #   Iterate through Admins in the Org's List and process as needed
    for new_admin in json_org_admins:
        try:
            #   Get matching admin record from live or None if it isn't granted yet
            admin = next((item for item in org_admins if item['email'] == new_admin['email']), None)

            if admin is None:
                org_perms = None
                net_perms = []
            else:
                org_perms = admin['orgAccess']
                net_perms = admin['networks']
                #   If there is an existing NetworkId that has not been specified,
                #   Copy existing so we don't update every time due to mismatched
                #   levels of detail
                for net_perm in net_perms:
                    net = next((i for i in new_admin['networks'] if i['id'] == net_perm['id']), None)
                    if net is None:
                        new_admin['networks'].append(net_perm)

            # Split logic based on existing permissions
            if org_perms == new_admin['orgAccess'] and net_perms == new_admin['networks']:
                logging.info("{0} already has the correct access".format(new_admin['name']))
            elif admin is None:
                logging.info("{0}{1} needs to be invited{2}".format(B, new_admin['name'], W))
                resp = meraki_extension.addnsadmin(apikey, org['id'], new_admin['email'], new_admin['name'], \
                    new_admin['orgAccess'], None, None, new_admin['networks'], True)
                logging.debug(resp)
            else:
                logging.info("{0}{1} needs updated permissions{2}".format(
                    B, new_admin['name'], W))
                resp = meraki_extension.updatensadmin(apikey, org['id'], admin['id'], new_admin['email'], \
                    new_admin['name'], new_admin['orgAccess'], None, None, new_admin['networks'], True)
                logging.debug(resp)
        except (KeyboardInterrupt, SystemExit):
            sys.exit()
        except Exception as e:
            str_err = "Error processing this Administrator: "
            logging.error("{0}{1}{2}: {3}\n{4}\n{5}".format(
                R, str_err, new_admin['name'], str(e), W, traceback.format_tb(e.__traceback__)
            ))

def process_orgs(username, actions):
    org_ids = [] # [org_id, org_name, org_url]
    adv_lics = [] # [org_id, org_name, adv_license, amp_mode, ids_mode, ids_rule]
    json_changelogs = [] # Hold all change log data so we can dump to a proper JSON file at the end

    print(G+"Logging in to Meraki Web Portal"+W)
    password = keyring.get_password('meraki', username)
    if password is None:
        logging.warning("{0}The keyring 'meraki' password is not set")
        sys.exit(2)

    payload = {
        'email': username,
        'password': password,
        # If any additional headers are used, validate the org_id split procedure
    }

    # Use 'with' to ensure the session context is closed after use.
    with requests.Session() as s:
        # Get the Organization List, this is the default redirect page after login
        host = 'https://account.meraki.com'
        p = s.post(host + '/login/login', data=payload)
        logging.debug("Cookies: " + str(s.cookies))
        soup = BeautifulSoup(p.text, 'html.parser')
        logging.debug("URL: " + str(p.url))
        
        # Parse out all Organization IDs, Names, and initiation URLs
        for item in soup.find_all('li'):
            org_a = item.find('a')
            org_name = org_a.get_text()
            org_id = org_a.get('href').split('=', 1)[1]
            org_url = org_a.get('href')
            org_ids.append([org_id, org_name, org_url])
            org_ids.sort(key=itemgetter(2))
            logging.debug("Org A tag: " + str(org_a))

        # Follow first Org Redirect and check for new confirmations
        print(G+"Checking for new Organization Access"+W)
        try:
            org_redirect = s.get(host + '/login/org_choose?eid=' + (org_ids[0])[0])
            logging.info("Initial Org Redirect URL: " + org_redirect.url)
            soup = BeautifulSoup(org_redirect.content, 'html.parser')
            forms = soup.find_all("form")
        except (KeyboardInterrupt, SystemExit):
            sys.exit()
        except Exception as e:
            print(R + "Error parsing html form" + W)
            logging.error("{0}Error parsing html form: {1}{2}\n{3}".format(
                R,W,str(e), traceback.format_tb(e.__traceback__)
            ))

        # Iterate through all new Organizations and accept access
        for conf in forms:
            # Get the form post url we need for this new Organization
            try:
                post_url = conf.get('action')
                logging.info("Post Url: " + post_url)
                post_split = post_url.split('/')
                if len(post_split) > 4 and post_split[4] == 'confirm_account_submit':
                    # Build form payload
                    token = conf.find('', {"name": "authenticity_token"}).get('value')
                    user_conf = conf.find('', {"name": "user_conf_key"}).get('value')
                    payload = {
                        'utf8': "%E2%9C%93",
                        'authenticity_token': token,
                        'user_conf_key': user_conf,
                        'commit': "Yes"
                    }

                    logging.info("{0}Found form: {1} - {2} - {3}{4}".format(
                        P, post_url, token, user_conf, W
                    ))

                    # Send Form Post to click the "Yes" button accepting access
                    logging.info(G+"Accepting Org Access: " + user_conf + W)
                    response_post = s.post(post_url, data=payload)
                    logging.debug("Accept Access Post Response: " + str(response_post))

                    # Set the host to the currently active server since we've issued another post
                    urlsplit = org_redirect.url.split('/')
                    host = urlsplit[0] + "//" + urlsplit[2]
            except (KeyboardInterrupt, SystemExit):
                sys.exit()
            except Exception as e:
                print(R + " Error parsing reply form" + W)
                logging.error("{0}Error parsing reply form: {1}{2}\n{3}".format(
                    R,W,str(e), traceback.format_tb(e.__traceback__)
                ))

        # Exit now if we don't need to get license or enable API
        if not ('l' in actions or 't' in actions or 'b' in actions or 'c' in actions):
            return adv_lics


        # Follow the Org Redirect, then open and parse the license details
        for org in org_ids:
            print(G + "Processing " + org[1] + W)
            advanced_license = amp_mode = ids_mode = ids_rule = False

            try:
                org_redirect = s.get(host + '/login/org_choose?eid=' + org[0])
                logging.debug(P + " Redirected URL:" + org_redirect.url + W)
                urlsplit = org_redirect.url.split('/')
            except (KeyboardInterrupt, SystemExit):
                sys.exit()
            except Exception as e:
                print(R + "Error accessing Organization" + W)
                logging.error("{0}Error accessing Organization: {1}{2}\n{3}".format(
                    R,W,str(e), traceback.format_tb(e.__traceback__)
                ))
                continue


            # Enable API access
            if 'b' in actions:
                print("  Querying API Access")
                try:
                    url = urlsplit[0] + '//' + urlsplit[2] + '/o/' + org[0] + '/manage/organization/edit'
                    org_manage = s.get(url)
                    soup = BeautifulSoup(org_manage.content, 'html.parser')
                    api_status = soup.find('', {"id": "organization_provisioning_api_enabled"}).get('checked')
                    if str(api_status) == 'None':
                        print(Y + "  Enabling API Access" + W)
                        url = urlsplit[0] + '//' + urlsplit[2] + '/o/' + org[0] + '/manage/organization'
                        token = soup.find('', {"name": "authenticity_token"}).get('value')
                        logging.debug(token)
                        payload = {
                            'authenticity_token': token,
                            'organization_provisioning_api_enabled': "1",
                            'organization[provisioning_api_enabled]': "1"
                        }
                        response_post = s.post(url, data=payload)
                except (KeyboardInterrupt, SystemExit):
                    sys.exit()
                except Exception as e:
                    print(R + "Error validating API Access" + W)
                    logging.error("{0}Error validating API Access: {1}{2}\n{3}".format(
                        R,W, str(e), traceback.format_tb(e.__traceback__)
                    ))

            # Parse License Details and Threat settings if needed 
            if 'l' in actions or 't' in actions:
                # Break apart the redirected url and rebuild it for the license page
                # TODO: Modularize this split since it will probably come up regularly
                print(G+"  Querying Advanced License"+W)
                urlsplit = org_redirect.url.split('/')
                logging.debug("URL Split: " + str(urlsplit))
                url = urlsplit[0] + '//' + urlsplit[2] + '/o/' + org[0] + '/manage/dashboard/license_info'
                org_license = s.get(url)
                logging.debug(P + "New Org URL: " + str(org_license.url) + W)

                # Parse the license table out by table row and store Advanced Security for return
                try:
                    soup = BeautifulSoup(org_license.content, 'html.parser')
                    licenses = soup.find("", {"id": "license_info_table"})
                    trs = licenses.find_all('tr')
                    logging.debug(p)
                    for l in trs:
                        if l.find('', {"class": "cfgq"}).text == "MX Advanced Security":
                            # TODO: Parse out Expiration date and store for future use
                            advanced_license = (l.find('', {"class": "cfgs"}).text == 'Enabled')
                except (KeyboardInterrupt, SystemExit):
                    sys.exit()
                except Exception as e:
                    print(R + "Error Retrieving Advanced License" + W)
                    logging.error("{0}Error Retrieving Advanced License: {1}{2}\n{3}".format(
                        R,W, str(e), traceback.format_tb(e.__traceback__)
                    ))

                # TODO: Scan for non-Advanced Threat gaps

                # All per network checks go here
                if 't' in actions or 'g' in actions:

                    # Find and parse out all networks
                    url = urlsplit[0] + '//' + urlsplit[2] + '/' + urlsplit[3]
                    url += '/n/' + urlsplit[5] + '/manage/organization/overview#t=network'
                    network_list = s.get(url)
                    logging.debug(P + "Network List URL: " + W + str(network_list.url))

                    try:
                        soup = BeautifulSoup(network_list.content, 'html.parser')
                        #network_div = soup.find("", {"id": "network_table"})
                        network_links = soup.find_all('a')
                        logging.debug(P + "Network Links: " + W + str(network_links))
                    except (KeyboardInterrupt, SystemExit):
                        sys.exit()
                    except Exception as e:
                        print(R + "Error parsing network list" + W)
                        logging.error("{0}Error parsing network list: {1}{2}\n{3}".format(
                            R,W,str(e), traceback.format_tb(e.__traceback__)
                        ))
                        continue

                    # Parse out advance security settings and validate them
                    if 't' in actions and advanced_license:
                        print(G + "Querying Security Filtering Settings" + W)
                        url = urlsplit[0] + '//' + urlsplit[2] + '/' + urlsplit[3]
                        url += '/n/' + urlsplit[5] + '/manage/configure/security_filtering'

                        sec_filter = s.get(url)
                        logging.debug(P + "Security Filtering URL: " + str(sec_filter.url) + W)

                        try:
                            soup = BeautifulSoup(sec_filter.content, 'html.parser')
                            amp_selector = soup.find("", {"id": "scanning_enabled_select"})
                            amp_mode = amp_selector.find("", {"selected": "selected"}).text

                            ids_selector = soup.find("", {"id": "ids_mode_select"})
                            ids_mode = ids_selector.find("", {"selected": "selected"}).text

                            ids_rule_selector = soup.find("", {"id": "ids_ruleset_select"})
                            ids_rule = ids_rule_selector.find("", {"selected": "selected"}).text

                            logging.info(B + "AMP: " + amp_mode + " IDS: " + ids_mode + " Ruleset: " + ids_rule + W)

                        except (KeyboardInterrupt, SystemExit):
                            sys.exit()
                        except Exception as e:
                            print(R + "Error Retrieving Threat Protection Settings" + W)
                            logging.error("{0}Error Retrieving Threat Protection Settings: {1}{2}\n{3}".format(
                                P,W,str(e), traceback.format_tb(e.__traceback__)
                            ))

                        # TODO: Parse all threat settings

                    adv_lics.append([org[0], org[1], advanced_license, amp_mode, ids_mode, ids_rule])

            if 'c' in actions:
                try:
                    # Break apart the redirected url and rebuild it for the license page
                    # TODO: Modularize this split since it will probably come up regularly
                    print(G+"  Retrieving Change Log"+W)
                    #url = urlsplit[0] + '//' + urlsplit[2] + '/o/' + org[0] + '/manage/organization/change_log'
                    url = urlsplit[0] + '//' + urlsplit[2] + '/o/' + org[0] + '/manage/organization/more_changes'
                    org_changes = s.get(url)
                    logging.debug(P + "Change Log URL: " + str(org_changes.url) + W)
                    logging.debug(org_changes.text)

                    changes_json = json.loads(org_changes.text)
                    j_filtered = {}
                    j_filtered['orgID'] = org[0]
                    j_filtered['orgName'] = org[1]
                    j_filtered['changes'] = []

                    # Epoch time at time lapse indicated
                    d_timelapse = int(time.time()) - i_timelapse
                    logging.info("{0}Ignoring Logs prior to {1}{2}".format(Y, str(d_timelapse), W))

                    for log_entry in changes_json['changes']:
                    # Remove this entry if it occured before time lapse
                        if i_timelapse != 0 and log_entry['time'] < d_timelapse:
                            continue

                        j_filtered['changes'].append(log_entry)

                    logging.debug("{0}Filtered Change Log: {1}{2}".format(P, W, json.dumps(j_filtered)))
                    json_changelogs.append(j_filtered)                    

                    # soup = BeautifulSoup(org_changes.text, 'html.parser')
                    # change_table = soup.find('', {"class": "flex-table-body"})
                    # trs = change_table.find_all('tr')
                    # logging.debug("{0}Change Log TDs: {1}{2}".format(P,W,trs))

                    # change_log = []
                    # for tr in trs:
                    #     change_record = {}
                    #     change_record["cl_org"] = org[0]
                    #     tds = tr.find_all('td')
                    #     for td in tds:
                    #         pass
                            # if ("cl_time" in td.class): change_record["cl_time"] = td.text
                            # if ("cl_admin" in td.class): change_record["cl_admin"] = td.text
                            # if ("cl_network" in td.class): change_record["cl_network"] = td.text
                            # if ("cl_ssid" in td.class): change_record["cl_ssid"] = td.text
                            # if ("cl_category" in td.class): change_record["cl_category"] = td.text
                            # if ("cl_label" in td.class): change_record["cl_label"] = td.text
                            # if ("cl_old_value" in td.class): change_record["cl_old_value"] = td.text
                            # if ("cl_new_value" in td.class): change_record["cl_new_value"] = td.text
                        # change_log.append(change_record)
                    
                    # json.dump(change_log, open(changelog_file, "a"))
                    
                except (KeyboardInterrupt, SystemExit):
                    sys.exit()
                except Exception as e:
                    print(R + "Error Retrieving Change Log" + W)
                    logging.error("{0}Error Retrieving Change Log: {1}{2}\n{3}".format(
                        R,W, str(e), traceback.format_tb(e.__traceback__)
                    ))

            # TODO: If requested actions is theat gaps, get the details here

        if 'c' in actions:
            # Write the Change Log JSON data out to file
            json.dump(json_changelogs, open(changelog_file, "w"))

        return adv_lics

def usage():
    print('ns_meraki.py -u <username> [options]')
    print(' -u <username>    :The email/username authenticate with')
    print(' --debug=LEVEL    : Sets the debug level of DEBUG, INFO, WARNING, ERROR, CRITICAL')
    print(' --log=           : Sets the file that debugging will be sent to')
    print(' -h               : Print this usage message')
    print(' -a <filename>    : Manage admins according to json file')
    print(' -l               : Summarize Licenses')
    print(' -t               : Print Threat gaps for security settings')
    print(' -o <filename>    : The output file to write json results to')
    print(' -c <filename>    : Retrieve and store Org Change Logs in <filename>')
    print(' -d <# seconds>   : Only include logs after <# seconds> in the past (604800 = 1 Week)')
    print(' -b               : Validate API access')
    print(' -g               : Update all Network Alert Rules')



if __name__ == "__main__":

    global json_admins, str_date, changelog_file, i_timelapse

    username = str_admin_file = ''
    admin = ['', 'read-only', '']
    output_file = ''
    # TODO Tab complete filenames

    actions = []

    #   Get command line arguments and parse for options
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hu:a:lto:c:bgd:', ['output-file=', 'log=', 'debug='])
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        sys.exit(2)

    str_date = datetime.date.today()

    log_level = logging.WARNING
    log_file = changelog_file = None
    i_timelapse = 0

    for opt, arg in opts:
        if opt == '-h':  # Print usage menu
            usage()
            sys.exit()
        elif opt == '--debug':  # Set debugging level
            log_level = getattr(logging, arg.upper(), None)
            if not isinstance(log_level, int):
                raise ValueError('Invalid log level: %s' % arg)
        elif opt == '--log':  # Set log file
            if len(arg) == 0:
                raise ValueError('Invalid log file name')
            log_file = arg
        elif opt == '-u':  # Email Address to login with
            username = arg
        elif opt == '-a':  # Action mode: Manage Admins
            actions.append('a')
            str_admin_file = arg
        elif opt == '-l':  # List Licenses ( Summarize non-advanced at the end )
            actions.append('l')
        elif opt == '-t':  # List Companies with their Threat Gaps
            actions.append('t')
        elif opt in ('-o', 'output-file='):  # Output changes to file
            output_file = arg
            actions.append('o')
        elif opt == '-c':  # Output change logs to file
            changelog_file = arg
            actions.append('c')
        elif opt == '-b':  # Process API Access validation
            actions.append('b')
        elif opt == '-g':  # Process API Network Alert Rules
            actions.append('g')
        elif opt == '-d':  # Set time-lapse argument for filtering to recent logs only
            i_timelapse = int(arg)

        # TODO: f for firewall rule gaps
        # TODO: f arg as a json file to match (does firewall rules contain a rule with policy, protocol, destPort)
        else:
            assert False, "unhandled option"

    #   Setup Logging Parameters
    if log_file is not None:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        logging.basicConfig(filename=log_file, level=log_level)
    else:
        logging.basicConfig(level=log_level)

    #   Make sure we have a username
    if username == '':
        print("the username parameter is required")
        usage()
        sys.exit(2)

    #   Make sure a file was entered
    if 'a' in actions:
        if len(str_admin_file) <= 0:
            print("a json file must be specified when using -a")
            usage()
            sys.exit(2)

        # Get the json config handed in 
        json_admins = json.load(open(str_admin_file, "r"))
        logging.debug("{0}JSON Admin file loaded: {1}{2}".format(P,W,json_admins))

    if 'a' in actions or 'g' in actions:
        #   Make sure we have an API Key stored
        if str(keyring.get_password("merakiapi", username)) == 'None':
            print("the username must have a 'merakiapi' key stored in keyring")
            sys.exit(2)

    if 'c' in actions:
        os.makedirs(os.path.dirname(changelog_file), exist_ok=True)


    main(username, actions)
