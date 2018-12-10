#!/usr/bin/python

import requests, json
from meraki import meraki


base_url = 'https://api.meraki.com/api/v0'

def getnetworkalerts(apikey, networkid, suppressprint=False):
    """
    Args:
        apikey: User's Meraki API Key
        netid: NetworkId for operation to be performed against
        suppressprint:
    Returns:
    """
    calltype = 'Network'

    geturl = '{0}/networks/{1}/alertSettings'.format(str(base_url), str(networkid))
    headers = {
        'x-cisco-meraki-api-key': format(str(apikey)),
        'Content-Type': 'application/json'
    }
    dashboard = requests.get(geturl, headers=headers)
    #
    # Call return handler function to parse Dashboard response
    #
    result = meraki.__returnhandler(dashboard.status_code, dashboard.text, calltype, suppressprint)
    return result


# Update a network alert
def updatenetworkalert(apikey, networkid, alerts, suppressprint=False):
    calltype = 'Network'
    puturl = '{0}/networks/{1}/alertSettings'.format(str(base_url), str(networkid))
    headers = {
        'x-cisco-meraki-api-key': format(str(apikey)),
        'Content-Type': 'application/json'
    }
    putdata = {}
    if alerts['defaultDestinations'] is not None:
        putdata['defaultDestinations'] = alerts['defaultDestinations']
    if alerts['alerts'] is not []:
        putdata['alerts'] = alerts['alerts']

    putdata = json.dumps(putdata)
    print(putdata)
    dashboard = requests.put(puturl, data=putdata, headers=headers)
    result = meraki.__returnhandler(dashboard.status_code, dashboard.text, calltype, suppressprint)
    return result


# Create a new dashboard administrator
# https://api.meraki.com/api_docs#create-a-new-dashboard-administrator
def addnsadmin(apikey, orgid, email, name, orgaccess=None, tags=None, tagaccess=None, networks=None,
             suppressprint=False):
    #
    # Confirm API Key has Admin Access Otherwise Raise Error
    #
    meraki.__hasorgaccess(apikey, orgid)
    calltype = 'Administrator'

    posturl = '{0}/organizations/{1}/admins'.format(str(base_url), str(orgid))
    headers = {
        'x-cisco-meraki-api-key': format(str(apikey)),
        'Content-Type': 'application/json'
    }

    posttags = []

    if orgaccess is None and tags is None and networks is None:
        print("Administrator accounts must be granted access to either an Organization, Networks, or Tags")
        return None

    if tags is not None and tagaccess is None:
        print("If tags are defined you must define matching access arguments.\nFor example, tags = ['tag1', 'tag2'], "
              "must have matching access arguments: tagaccess = 'full', 'read-only'")
        return None
    elif tagaccess is not None and tags is None:
        print("If tag access levels are defined you must define matching tag arguments\nFor example, tags = "
              "['tag1', 'tag2'] must have matching access arguments: tagaccess = 'full', 'read-only'")
        return None
    elif tagaccess is None and tags is None:
        pass
    elif len(tags) != len(tagaccess):
        print("The number of tags and access arguments must match.\n")
        print("For example, tags = ['tag1', 'tag2'] must have matching access arguments: tagaccess = "
              "['full', 'read-only']")
        return None
    elif tags is not None and tagaccess is not None:
        x = 0
        while x < len(tags):
            posttags.append({'tag': tags[x], 'access': tagaccess[x]})
            x += 1
    else:
        pass

    postnets = networks
    
    postdata = []
    if len(posttags) == 0 and len(postnets) == 0:
        postdata = {
            'orgAccess': orgaccess,
            'email': format(str(email)),
            'name': format(str(name))
        }

    elif len(posttags) > 0 and len(postnets) == 0:
        postdata = {
            'name': format(str(name)),
            'email': format(str(email)),
            'orgAccess': orgaccess,
            'tags': posttags
        }

    elif len(postnets) > 0 and len(posttags) == 0:
        postdata = {
            'name': format(str(name)),
            'email': format(str(email)),
            'orgAccess': orgaccess,
            'networks': postnets
        }

    elif len(postnets) > 0 and len(posttags) > 0:
        postdata = {
            'name': format(str(name)),
            'email': format(str(email)),
            'orgAccess': orgaccess,
            'tags': posttags,
            'networks': postnets
        }
    dashboard = requests.post(posturl, data=json.dumps(postdata), headers=headers)
    #
    # Call return handler function to parse Dashboard response
    #
    result = meraki.__returnhandler(dashboard.status_code, dashboard.text, calltype, suppressprint)
    return result


# Update an administrator
# https://api.meraki.com/api_docs#update-an-administrator
def updatensadmin(apikey, orgid, adminid, email, name=None, orgaccess=None, tags=None, tagaccess=None,
                networks=None, suppressprint=False):
    #
    # Confirm API Key has Admin Access Otherwise Raise Error
    #
    meraki.__hasorgaccess(apikey, orgid)
    calltype = 'Administrator'

    puturl = '{0}/organizations/{1}/admins/{2}'.format(str(base_url), str(orgid), str(adminid))
    headers = {
        'x-cisco-meraki-api-key': format(str(apikey)),
        'Content-Type': 'application/json'
        }

    puttags = []

    if orgaccess is None and tags is None and networks is None and name is None:
        print("Administrator account updates must include Organization, Networks, or Tags permission changes or an "
              "updated name attribute")
        return None

    if tags is not None and tagaccess is None:
        print("If tags are defined you must define matching access arguments.\nFor example, tags = ['tag1', 'tag2'], "
              "must have matching access arguments: tagaccess = 'full', 'read-only'")
        return None
    elif tagaccess is not None and tags is None:
        print("If tag access levels are defined you must define matching tag arguments\nFor example, tags = "
              "['tag1', 'tag2'] must have matching access arguments: tagaccess = 'full', 'read-only'")
        return None
    elif tagaccess is None and tags is None:
        pass
    elif len(tags) != len(tagaccess):
        print("The number of tags and access arguments must match.\n")
        print("For example, tags = ['tag1', 'tag2'] must have matching access arguments: tagaccess = "
              "['full', 'read-only']")
        return None
    elif tags is not None and tagaccess is not None:
        x = 0
        while x < len(tags):
            puttags.append({'tag': tags[x], 'access': tagaccess[x]})
            x += 1
    else:
        pass

    putnets = networks

    putdata = []

    if name is not None:
        if len(puttags) == 0 and len(putnets) == 0:
            putdata = {
                'orgAccess': orgaccess,
                'email': format(str(email)),
                'name': format(str(name))
            }

        elif len(puttags) > 0 and len(putnets) == 0:
            putdata = {
                'name': format(str(name)),
                'email': format(str(email)),
                'orgAccess': orgaccess,
                'tags': puttags
                }

        elif len(putnets) > 0 and len(puttags) == 0:
            putdata = {
                'name': format(str(name)),
                'email': format(str(email)),
                'orgAccess': orgaccess,
                'networks': putnets
                }

        elif len(putnets) > 0 and len(puttags) > 0:
            putdata = {
                'name': format(str(name)),
                'email': format(str(email)),
                'orgAccess': orgaccess,
                'tags': puttags,
                'networks': putnets
                }

    elif name is None:
        if len(puttags) > 0 and len(putnets) == 0:
            putdata = {
                'email': format(str(email)),
                'orgAccess': orgaccess,
                'tags': puttags
                }

        elif len(putnets) > 0 and len(puttags) == 0:
            putdata = {
                'email': format(str(email)),
                'orgAccess': orgaccess,
                'networks': putnets
                }

        elif len(putnets) > 0 and len(puttags) > 0:
            putdata = {
                'email': format(str(email)),
                'orgAccess': orgaccess,
                'tags': puttags,
                'networks': putnets
                }

    dashboard = requests.put(puturl, data=json.dumps(putdata), headers=headers)
    #
    # Call return handler function to parse Dashboard response
    #
    result = meraki.__returnhandler(dashboard.status_code, dashboard.text, calltype, suppressprint)
    return result