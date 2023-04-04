#!/usr/bin/python3
"""
AD_Account_Lockout_Status.py, AD_Account_Lockout_Status.ps1

Return Codes:
	3 = Unknown (script failed without a more appropriate return code)
	2 = Critical (account locked out)
	1 = Warning (not used here)
	0 = OK (account not locked out)
"""

from ldap3 import Server, Connection, SAFE_SYNC, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, ServerPool
import argparse, os, socket

#==============================================================================
def isValid(lanID:str, basedn:str, conn:Connection):
    """Check the supplied is a valid username

    Args:
        lanID (str): lanID
        basedn (str): Base Domain Name
        conn (Connection): Connection object to some server

    Returns:
        Boolean: True/False if valid 
    """
    # Search filter based on Users with samAccountName matching supplied lanID
    search_filter = "(&(objectCategory=User)(samAccountName=" + lanID + "))"
    # Search based on samAccountName
    search_attribute = ["samAccountName"]
    # If the username exists return true else return false
    if conn.search(basedn, search_filter, attributes=search_attribute)[0]:
        return True
    else:
        return False
#==============================================================================

#==============================================================================
def isLocked(lanID:str, basedn:str, conn:Connection):
    """Check if a user is locked out using ldap query

    Args:
        lanID (str): LAN ID being tested
        basedn (str): Base Domain Name
        conn (Connection): Connection object to some server

    Returns:
        int: Return code following Nagios standard 2,1,0,3
    """

    # Search filter, looking at User object with a samAccountName equal to lanID with a lockoutTime >= 1
    search_filter = "(&(objectCategory=User)(samAccountName=" + lanID + ")(lockoutTime>=1))" #all users with same name as user
    search_attribute = ["samAccountName"]

    # Search the using search_filter, if connection returns true account is locked out
    if conn.search(basedn, search_filter, attributes=search_attribute)[0]:
       # logger.critical("Account " + lanID + " is locked out.")
        returnCode = 2
    # Else account not locked out
    else:
        #logger.info("Account " + lanID + " is not locked out")
        returnCode = 0

    return returnCode
#==============================================================================

# MAIN
if __name__ == "__main__":
    
    # Standard logger
    logger= nagiosStandardFunctions.standardLogging("check_account_lockout.py","logs","1.0.0", "fh", True)
    logger.info(os.path.basename(__file__) + " stated")
    #GET COMMAND INPUT
    opts = argparse.ArgumentParser(prog="AD_Account_Lockout_Checker", formatter_class=argparse.ArgumentDefaultsHelpFormatter)


    opts.add_argument(
        "-u", "--username",
        required=True,
        default=None,
        type=str,
        help="String(username): Username credential to access server."
    )

    opts.add_argument(
        "-l", "--LANID",
        required=True,
        default=None,
        type=str,
        help="String(LANDID): LAN ID to be tested."
    )

    opts.add_argument(
        "-b", "--basedn",
        required=True,
        default=None,
        type=str,
        help="String(basedn): Base domain name."
    )

    # BUILD ARGS ARRAY
    args = opts.parse_args()

    # NSLOOKUP -> for each addrinfo in target, append to a list the ip address
    ip_list = list({addr[-1][0] for addr in socket.getaddrinfo('up.acpt.upc', 0, 0, 0, 0)})
    print(ip_list)
    # get just the username --> removes the UP\ from the begining
    username = "username"
    password = "password"

    returnCode = 3
    conn = Connection(
                    ServerPool(ip_list),
                    user=args.username, 
                    password=password, 
                    client_strategy=SAFE_SYNC, 
                    auto_bind=True)

    # Try to bind
    valid_bind = isValid(args.LANID, args.basedn ,conn)
    if valid_bind:
        msg = f"Valid bind | {args.basedn}"
        logger.info(msg)
        # if the bind is valid then check to if the account is locked
        account_locked_return_code = isLocked(args.LANID, args.basedn ,conn)
        if account_locked_return_code == 2:
            msg = f"Lan ID: {args.LANID} is locked out"
            logger.critical(msg)
            returnCode = 2
        else:
            msg = f"Lan ID: {args} is not locked out"
            logger.info(msg)
            returnCode = 0
    else:
        msg = f"Invalid bind | {args.basedn}"
        logger.critical(msg)
        returnCode = 2
       
    #msg = nagiosStandardFunctions.exitMessages(returnCode)
    logger.info(os.path.basename(__file__) + " finished")
    nagiosStandardFunctions.nagiosExit(logger,returnCode,msg,"")
