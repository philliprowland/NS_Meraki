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

def main(apikey, username, debug=False):

    # TODO: Build Errors Array for exception reporting
    # TODO: Build Debug Logger method to keep console clean

    m_orgs = []

    orgs = meraki.myorgaccess(apikey, (not debug))
    if debug: print(orgs)


    for org in orgs:

        # TODO: Can I dynamically add to the org dictionary of each element
        print(G+"Checking Administrators in " + org['name'] + ":"+W)
        grant_org_admin(apikey, org['id'], 'meraki_vpn@netsmartai.com', "NetSmart API", debug)



        # m_org = m_organization(org['id'], org['name'])
        # m_orgs.append(m_org)


    org_lics = get_org_lics(username, debug)
    if debug:
        print("Return Value: " + str(org_lics))

def grant_org_admin(apikey, orgid, email, name, debug=False):
    org_admins = meraki.getorgadmins(apikey, orgid, (not debug))
    if debug:
        print(org_admins)
    try:
        notadmin = True
        for admin in org_admins:
            print(G+"  " + admin['name'] + " has " + admin['orgAccess'] + " access"+W)
            if admin['email'] == email:
                notadmin = False

        if (notadmin):
            print(Y+"  "+name + " not found, adding..."+W)
            meraki.addadmin(apikey, orgid, email, name, 'full')
    except TypeError:
        print(R+"  Error processing this Organization"+W)


def get_org_lics(username, debug=False):

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
        if debug: print("Cookies: " + str(s.cookies))
        soup = BeautifulSoup(p.text, 'html.parser')
        if debug: print("URL: " + str(soup.url))
        
        # Parse out all Organization IDs, Names, and initiation URLs
        for item in soup.find_all('li'):
            org_a = item.find('a')
            org_name = org_a.get_text()
            org_id = org_a.get('href').split('=', 1)[1]
            org_url = org_a.get('href')
            org_ids.append([org_id, org_name, org_url])
            if (debug): print("Org A tag: " + str(org_a))

        # Follow the Org Redirect, then open and parse the license details
        for org in org_ids:
            print(G+"Accessing " + org[1] +W)
            org_redirect = s.get(host + '/login/org_choose?eid=' + org[0])

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
                if (debug): print(p)
                for l in trs:
                    if l.find('', {"class": "cfgq"}).text == "MX Advanced Security":
                        # TODO: Parse out Expiration date and store for future use
                        adv_lics.append([org[0], org[1], l.find('', {"class": "cfgs"}).text])
            except:
                print(R+"  Error Retrieving Advanced License"+W)

            # Enable API access
            print(G+"  Querying API Access"+W)
            try:
                url = urlsplit[0] + '//' + urlsplit[2] + '/o/' + org[0] + '/manage/organization/edit'
                org_manage = s.get(url)
                soup = BeautifulSoup(org_manage.content, 'html.parser')
                api_status = soup.find('', {"id": "organization_provisioning_api_enabled"}).get('checked')
                if str(api_status) == 'None':
                    print(Y+"  Enabling API Access"+W)
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
            except:
                print(R+"  Error validating API Access"+W)

        return adv_lics

""" Can't get details of License or Advanced Protection Settings here
        orgNetworks = meraki.getnetworklist(apikey, org['id'])
        for network in orgNetworks:
            netDetail = meraki.getnetworkdetail(apikey, network['id'])
            print(netDetail)
"""

def usage():
    print('get_orgs.py -k <keyfile> -u <username>')


if __name__ == "__main__":
    keyfile = username = ''

    #   Get command line arguments and parse for options
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hk:u:')
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            usage()
            sys.exit()
        elif opt == '-k':
            keyfile = arg
        elif opt == '-u':
            username = arg
        else:
            assert False, "unhandled option"

    #   Make sure we have a Key File option value
    if keyfile == '':
        print("the keyfile parameter is required")
        usage()
        sys.exit(2)
    #   Make sure we have a username
    if username == '':
        print("the username parameter is required")
        usage()
        sys.exit(2)

    #   Open Specified Key File and read API Key into variable "apikey"
    try:
        keyhandle = open(keyfile, "r")

        if keyhandle.mode == 'r':
            apikey = keyhandle.read().rstrip()
    except:
        print("Error opening specified API Key File.")
        sys.exit(2)

    main(apikey, username)
