class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

print(bcolors.HEADER + "Header")
print(bcolors.OKBLUE + "OKBlue")
print(bcolors.OKGREEN + "OKGreen")
print(bcolors.WARNING + "Warning")
print(bcolors.FAIL + "Fail")
print(bcolors.ENDC + "ENDC")
print(bcolors.BOLD + "Bold")
print(bcolors.UNDERLINE + "Underline")