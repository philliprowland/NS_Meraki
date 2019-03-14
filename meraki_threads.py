import threading
import time

def ProcessOrg(Name, net_count):
    print(Name + ": Get Password")
    print(Name + ": Start Session")
    print(Name + ": Follow Org Redirect")
    print(Name + ": Enable API")
    print(Name + ": Get License Detail")
    print(Name + ": Get Change Logs")
    print(Name + ": Get Security Events")
    print(Name + ": API - Get Network Lists")
    print(Name + ": API - Admins")
    for i in range(net_count):
        print(Name + ": Net" + str(i) + ": Get Security Filtering")
        print(Name + ": Net" + str(i) + ": API - Network Alerts")
    print(Name + ": Close Session")
    print(Name + ": Append Results")
    print(Name + ": Done!")



threading.Thread(target=ProcessOrg, args=["AJV",2]).start()
threading.Thread(target=ProcessOrg, args=["Universal",10]).start()
threading.Thread(target=ProcessOrg, args=["FlowRite",1]).start()
threading.Thread(target=ProcessOrg, args=["Michigan Ag",9]).start()