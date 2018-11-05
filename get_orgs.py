#!/usr/bin/python

import sys, getopt, requests
from meraki_classes import m_organization
from meraki import meraki
from bs4 import BeautifulSoup
import keyring

# Define Console Color Constants
W = '\033[0m'  # white (normal)
R = '\033[91m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[94m'  # blue
P = '\033[95m'  # purple
Y = '\033[93m'  # yellow

def main(username, actions, admin):
    if debug:
        print(P+"Debugging Enabled"+W)
    verbose = 'v' in actions

    # TODO: Build Errors Array for exception reporting
    # TODO: Build Debug Logger method to keep console clean

    m_orgs = []

    # Accept Invitations, Enable API and do all Org related actions
    org_lics = process_orgs(username, actions)
    if debug:
        print(P+"Return Value: " + str(org_lics)+W)


    # Run all of the API based calls
    if 'a' in actions:
        apikey = keyring.get_password('merakiapi', username)
        orgs = meraki.myorgaccess(apikey, (not debug))
        if debug:
            print(P + orgs + W)

        for org in orgs:
            # TODO: Can I dynamically add to the org dictionary of each element

            print(G + "Processing " + org['name'] + W )

            # Add administrators if requested
            if 'a' in actions:
                if verbose:
                    print(B + "Checking Administrators in " + org['name'] + ":" + W)
                grant_org_admin(apikey, org['id'], admin)
                # TODO: Make this call dynamic based on the parameters


            # m_org = m_organization(org['id'], org['name'])
            # m_orgs.append(m_org)


def grant_org_admin(apikey, orgid, new_admin):
    org_admins = meraki.getorgadmins(apikey, orgid, (not debug))
    if debug:
        print(org_admins)
    try:
        notadmin = True
        for admin in org_admins:
            if verbose:
                print(G + "  " + admin['name'] + " has " + admin['orgAccess'] + " access" + W)
            if admin['email'] == new_admin[0]:
                notadmin = False

        if (notadmin):
            if verbose:
                print(Y + "  " + new_admin[2] + " not found, adding..." + W)
            resp = meraki.addadmin(apikey, orgid, new_admin[0], new_admin[2] , new_admin[1])
            if debug:
                print(resp)
    except TypeError:
        print(R + "  Error processing this Organization" + W)
    except (KeyboardInterrupt, SystemExit):
        raise


def process_orgs(username, actions):
    org_ids = [] # [org_id, org_name, org_url]
    adv_lics = [] # [org_id, org_name, adv_license]

    print(G+"Logging in to Meraki Web Portal"+W)
    password = keyring.get_password('meraki', username)
    payload = {
        'email': username,
        'password': password,
        # If any additional headers are used, validate the org_id split procedure
    }

    # Use 'with' to ensure the session context is closed after use.
    with requests.Session() as s:
        # Get the Organization List, this is the default redirect page after login
        host = 'https://n94.meraki.com'
        p = s.post(host + '/login/login', data=payload)
        if debug:
            print("Cookies: " + str(s.cookies))
        soup = BeautifulSoup(p.text, 'html.parser')
        if debug:
            print("URL: " + str(soup.url))
        
        # Parse out all Organization IDs, Names, and initiation URLs
        for item in soup.find_all('li'):
            org_a = item.find('a')
            org_name = org_a.get_text()
            org_id = org_a.get('href').split('=', 1)[1]
            org_url = org_a.get('href')
            org_ids.append([org_id, org_name, org_url])
            if debug:
                print("Org A tag: " + str(org_a))

        # Follow first Org Redirect and check for new confirmations
        print(G+"Checking for new Organization Access"+W)
        org_redirect = s.get(host + '/login/org_choose?eid=' + (org_ids[0])[0])
        if debug:
            print(org_redirect.url)
        soup = BeautifulSoup(org_redirect.content, 'html.parser')
        forms = soup.find_all("form")

        # Iterate through all new Organizations and accept access
        for conf in forms:
            # Get the form post url we need for this new Organization
            post_url = conf.get('action')
            if post_url.split('/')[4] == 'confirm_account_submit':
                # Build form payload
                token = conf.find('', {"name": "authenticity_token"}).get('value')
                user_conf = conf.find('', {"name": "user_conf_key"}).get('value')
                payload = {
                    'utf8': "%E2%9C%93",
                    'authenticity_token': token,
                    'user_conf_key': user_conf,
                    'commit': "Yes"
                }

                if debug:
                    print("Found form: " + post_url + " - " + token + " - " + user_conf)

                # Send Form Post to click the "Yes" button accepting access
                if verbose:
                    print(G+"  Accepting Org Access: " + user_conf + W)
                response_post = s.post(post_url, data=payload)
                if debug:
                    print(str(response_post))

                # Set the host to the currently active server since we've issued another post
                urlsplit = org_redirect.url.split('/')
                host = urlsplit[0] + "//" + urlsplit[2]

        # Exit now if we don't need to get license or enable API
        if not ('l' in actions or 't' in actions or 'b' in actions):
            return adv_lics


        # Follow the Org Redirect, then open and parse the license details
        for org in org_ids:
            print("Processing " + org[1])
            try:
                org_redirect = s.get(host + '/login/org_choose?eid=' + org[0])
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                print(R + " Error accessing Organization" + W)
                print(str(e))


            # Enable API access
            if 'b' in actions:
                print("  Querying API Access")
                try:
                    urlsplit = org_redirect.url.split('/')
                    url = urlsplit[0] + '//' + urlsplit[2] + '/o/' + org[0] + '/manage/organization/edit'
                    org_manage = s.get(url)
                    soup = BeautifulSoup(org_manage.content, 'html.parser')
                    api_status = soup.find('', {"id": "organization_provisioning_api_enabled"}).get('checked')
                    if str(api_status) == 'None':
                        print(Y + "  Enabling API Access" + W)
                        url = urlsplit[0] + '//' + urlsplit[2] + '/o/' + org[0] + '/manage/organization'
                        token = soup.find('', {"name": "authenticity_token"}).get('value')
                        if debug:
                            print(token)
                        payload = {
                            'authenticity_token': token,
                            'organization_provisioning_api_enabled': "1",
                            'organization[provisioning_api_enabled]': "1"
                        }
                        response_post = s.post(url, data=payload)
                        if debug:
                            handle = open(org[1] + '-manage_org.html', "w")
                            handle.write(str(response_post.content))
                            handle.close()
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as e:
                    print(R + "  Error validating API Access" + W)
                    print(str(e))


            # Parse License Details if needed
            if 'l' in actions or 't' in actions:
                # Break apart the redirected url and rebuild it for the license page
                # TODO: Modularize this split since it will probably come up regularly
                print(G+"  Querying Advanced License"+W)
                urlsplit = org_redirect.url.split('/')
                if (debug): print("URL Split: " + str(urlsplit))
                url = urlsplit[0] + '//' + urlsplit[2] + '/o/' + org[0] + '/manage/dashboard/license_info'
                org_license = s.get(url)
                if (debug): print("New Org URL: " + str(org_license.url))

                # Write out the HTML response if debugging so we can review for refactoring
                if (debug):
                    handle = open(org[1] + '-get_adv_lics.html', "w")
                    handle.write(str(org_license.content))
                    handle.close()

                # Parse the license table out by table row and store Advanced Security for return
                try:
                    soup = BeautifulSoup(org_license.content, 'html.parser')
                    license = soup.find("", {"id": "license_info_table"})
                    trs = license.find_all('tr')
                    if debug:
                        print(p)
                    for l in trs:
                        if l.find('', {"class": "cfgq"}).text == "MX Advanced Security":
                            # TODO: Parse out Expiration date and store for future use
                            advanced_license = (l.find('', {"class": "cfgs"}).text == 'Enabled')
                            adv_lics.append([org[0], org[1], advanced_license])
                except (KeyboardInterrupt, SystemExit):
                    raise
                except:
                    print(R+"  Error Retrieving Advanced License"+W)


                if 't' in actions:
                    # TODO: Parse all threat settings
                    print('Threat analysis not implemented yet')

            # TODO: If requested actions is theat gaps, get the details here

        return adv_lics

def usage():
    msg = 'get_orgs.py [-d] [-h] -e <login email> [-a <new admin email> -n <admin name>]'
    msg += ' [-u <admin email>] [-p <new permission>] [-r <remove admin>] [-l] [-t] [-o] [-c]'
    print(msg)
    print(' d: Print Debugging messages')
    print(' h: Print this usage message')
    print(' e: The email/username authenticate with')
    print(' a: Add this email to all organizations as admin')
    print(' n: The name of the new admin')
    print(' u: Update the permissions of this Admin')
    print(' p: "full"|"read-only" for new/updated admin')
    print(' r: Revoke rights from this Admin')
    print(' l: Summarize Licenses')
    print(' t: Print Threat gaps for security settings')
    print(' o: The output file to write json results to')
    print(' c: Limit json output file to a diff from this file')
    print(' b: Validate API access')



if __name__ == "__main__":

    global debug, verbose

    keyfile = username = ''
    admin = ['', 'read-only', '']
    output_file = ''
    # TODO Convert admins to a dictionary

    actions = []

    #   Get command line arguments and parse for options
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'dhe:a:n:u:p:r:lto:cvb', ['output-file='])
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        sys.exit(2)

    # print(opts)
    # print(args)

    debug = verbose = False

    for opt, arg in opts:
        if opt == '-h': # Print usage menu
            usage()
            sys.exit()
        elif opt == '-d': # Set debugging to on
            debug = True
        elif opt == '-e': # Email Address to login with
            username = arg
        elif opt == '-a': # Action mode: Add Admins
            actions.append('a')
            admin[0] = arg
        elif opt == '-n': # Admin Name
            admin[2] = arg
        elif opt == '-u': # Action mode: Update Admins
            actions.append('u')
            admin[0] = arg
        elif opt == '-p': # Permission to add/update for Admins
            admin[1] = arg
        elif opt == '-r': # Remove Admins
            actions.append('r')
            admin[0] = arg
        elif opt == '-l': # List Licenses ( Summarize non-advanced at the end )
            actions.append('l')
        elif opt == '-t': # List Companies with their Threat Gaps
            actions.append('t')
        elif opt in ('-o', 'output-file='): # Output changes to file
            output_file = arg
            actions.append('o')
        elif opt == '-c': # Output only changes to file
            actions.append('c')
        elif opt == '-v': # Process and print verbosely (slower)
            verbose = True
        elif opt == '-b': # Process API Access validation
            actions.append('b')
        # TODO: f for firewall rule gaps
        # TODO: f arg as a json file to match (does firewall rules contain a rule with policy, protocol, destPort)
        else:
            assert False, "unhandled option"

    #   Make sure we have a username
    if username == '':
        print("the username parameter is required")
        usage()
        sys.exit(2)


    #   Make sure not more than one admin modification is selected
    admin_count = 0
    if 'a' in actions:
        admin_count += 1
        if admin[2] == '':
            print('You must include a name with the -n parameter')
            sys.exit()
        #   Make sure we have a permission if we are to add an admin
        # TODO Validate permission options
    if 'u' in actions:
        admin_count += 1

        #   Make sure we have a permission if we are to update an admin
        # TODO Validate permission options
        print('Update Admin feature not implemented yet')
    if 'r' in actions:
        admin_count += 1
    if admin_count > 1:
        print('Cannot select multiple administrator operations in one run')
        sys.exit()

    # ALL API prerequisites checked here
    if admin_count == 1: # Or any other actions using API
        #   Make sure we have an API Key stored
        if str(keyring.get_password("merakiapi", username)) == 'None':
            print("the username must have a 'merakiapi' key stored in keyring")
            sys.exit(2)



    main(username, actions, admin)
