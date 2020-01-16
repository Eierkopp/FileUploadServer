#!/usr/bin/python3

import base64
import binascii
import datetime
import dateutil.parser
import dbus
import hashlib
import json
import logging
import os
from pprint import pprint
import pytz
import requests
import time
import OpenSSL


DEFAULT_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"
DOMAIN = "domain.name"
ACCOUNT_KEY = "account.key"
DOMAIN_KEY = "domain.key"
MIN_CERT_VALIDITY_DAYS = 20


INTERMEDIATE_CERT = b"""-----BEGIN CERTIFICATE-----
MIIFjTCCA3WgAwIBAgIRANOxciY0IzLc9AUoUSrsnGowDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTYxMDA2MTU0MzU1
WhcNMjExMDA2MTU0MzU1WjBKMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDEjMCEGA1UEAxMaTGV0J3MgRW5jcnlwdCBBdXRob3JpdHkgWDMwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCc0wzwWuUuR7dyXTeDs2hjMOrX
NSYZJeG9vjXxcJIvt7hLQQWrqZ41CFjssSrEaIcLo+N15Obzp2JxunmBYB/XkZqf
89B4Z3HIaQ6Vkc/+5pnpYDxIzH7KTXcSJJ1HG1rrueweNwAcnKx7pwXqzkrrvUHl
Npi5y/1tPJZo3yMqQpAMhnRnyH+lmrhSYRQTP2XpgofL2/oOVvaGifOFP5eGr7Dc
Gu9rDZUWfcQroGWymQQ2dYBrrErzG5BJeC+ilk8qICUpBMZ0wNAxzY8xOJUWuqgz
uEPxsR/DMH+ieTETPS02+OP88jNquTkxxa/EjQ0dZBYzqvqEKbbUC8DYfcOTAgMB
AAGjggFnMIIBYzAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADBU
BgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEBATAwMC4GCCsGAQUFBwIB
FiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQub3JnMB0GA1UdDgQWBBSo
SmpjBH3duubRObemRWXv86jsoTAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3Js
LnJvb3QteDEubGV0c2VuY3J5cHQub3JnMHIGCCsGAQUFBwEBBGYwZDAwBggrBgEF
BQcwAYYkaHR0cDovL29jc3Aucm9vdC14MS5sZXRzZW5jcnlwdC5vcmcvMDAGCCsG
AQUFBzAChiRodHRwOi8vY2VydC5yb290LXgxLmxldHNlbmNyeXB0Lm9yZy8wHwYD
VR0jBBgwFoAUebRZ5nu25eQBc4AIiMgaWPbpm24wDQYJKoZIhvcNAQELBQADggIB
ABnPdSA0LTqmRf/Q1eaM2jLonG4bQdEnqOJQ8nCqxOeTRrToEKtwT++36gTSlBGx
A/5dut82jJQ2jxN8RI8L9QFXrWi4xXnA2EqA10yjHiR6H9cj6MFiOnb5In1eWsRM
UM2v3e9tNsCAgBukPHAg1lQh07rvFKm/Bz9BCjaxorALINUfZ9DD64j2igLIxle2
DPxW8dI/F2loHMjXZjqG8RkqZUdoxtID5+90FgsGIfkMpqgRS05f4zPbCEHqCXl1
eO5HyELTgcVlLXXQDgAWnRzut1hFJeczY1tjQQno6f6s+nMydLN26WuU4s3UYvOu
OsUxRlJu7TSRHqDC3lSE5XggVkzdaPkuKGQbGpny+01/47hfXXNB7HntWNZ6N2Vw
p7G6OfY+YQrZwIaQmhrIqJZuigsrbe3W+gdn5ykE9+Ky0VgVUsfxo52mwFYs1JKY
2PGDuWx8M6DlS6qQkvHaRUo0FMd8TsSlbF0/v965qGFKhSDeQoMpYnwcmQilRh/0
ayLThlHLN81gSkJjVrPI0Y8xCVPB4twb1PFUd2fPM3sA1tJ83sZ5v8vgFv2yofKR
PB0t6JzUA81mSqM3kxl5e+IZwhYAyO0OTg3/fs8HqGTNKd9BqoUwSRBzp06JMg5b
rUCGwbCUDI0mxadJ3Bz4WxR6fyNpBK2yAinWEsikxqEt
-----END CERTIFICATE-----"""

LOCATIONS = [("/etc/ssl/certs/eierkopp.crt",
              "/etc/ssl/private/eierkopp.key")]

SERVICES = ["postfix", "dovecot"]

logging.basicConfig(level=logging.DEBUG)


def b64(b):
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def enc_num(n):
    s = "%x" % n
    s = "0" * (len(s) % 2) + s
    return b64(binascii.unhexlify(s))


def get_private_key(fname):
    with open(fname) as f:
        return OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, f.read())


def get_csr(domain, dkey):
    csr = OpenSSL.crypto.X509Req()
    csr.get_subject().CN = domain
    csr.set_version(2)
    csr.set_pubkey(dkey)
    csr.sign(dkey, "sha256")
    bytes = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_ASN1, csr)
    return b64(bytes)


def get_header(akey):
    pk = akey.to_cryptography_key().public_key().public_numbers()
    header = dict(alg="RS256", jwk=dict(e=enc_num(pk.e), kty="RSA", n=enc_num(pk.n)))
    return header


def get_account_print(header):
    key_json = json.dumps(header["jwk"], sort_keys=True, separators=(',', ':'))
    key_thumb = b64(hashlib.sha256(key_json.encode('utf8')).digest())
    return key_thumb


def get_signature(data, pkey):
    return b64(OpenSSL.crypto.sign(pkey, data.encode("latin1"), "sha256"))


def enc_header_with_nonce(header, directory):
    nonce = requests.get(directory["newNonce"]).headers["Replay-Nonce"]
    header_with_nonce = header.copy()
    header_with_nonce.update({"nonce": nonce})
    enc_header = b64(json.dumps(header_with_nonce).encode("latin1"))
    return enc_header


def make_request(url, header, payload, akey, directory):
    header["url"] = url
    enc_payload = "" if payload is None else b64(json.dumps(payload).encode("utf8"))
    enc_header = enc_header_with_nonce(header, directory)
    body = {"protected": enc_header,
            "payload": enc_payload,
            "signature": get_signature(enc_header + "." + enc_payload, akey)}
    return requests.post(url,
                         json=body,
                         headers={'content-type': 'application/jose+json'})


def get_directory():
    response = requests.get(DEFAULT_DIRECTORY_URL)
    return response.json()


def sign_in(header, akey, directory):
    resp = make_request(directory["newAccount"],
                        header,
                        {
                            "termsOfServiceAgreed": True,
                        },
                        akey,
                        directory)
    if resp.status_code in [200, 201, 204]:
        logging.getLogger(__name__).info("Account registered")
    elif resp.status_code == 409:
        logging.getLogger(__name__).info("Signed in to existing account")
    else:
        raise Exception("Failed to sign in: " + resp.reason + "\n" + resp.text)
    return resp.json(), resp.headers


def http01_challenge(data, directory):
    resp = make_request(data["authorizations"][0],
                        header,
                        None,
                        akey,
                        directory)
    resp_json = resp.json()

    challenges = resp_json["challenges"]
    for c in challenges:
        if c["type"] != "http-01":
            continue
        return c["status"], c["token"], c["url"]
    raise Exception("No challenge found")


def wait_for_auth_file(domain, token, content):
    url = "http://%s/.well-known/acme-challenge/%s" % (domain, token)
    for i in range(30):
        data = requests.get(url).text
        if data == content:
            return
        time.sleep(1)
        logging.getLogger(__name__).info("Waiting for auth file at %s" % url)
    raise Exception("Auth file missing from %s" % url)


def wait_for_verification(uri):
    for i in range(10):
        time.sleep(1)
        status = requests.get(uri).json()
        if status['status'] == "valid":
            return
        time.sleep(5)
    raise Exception("Domain %s not verified" % uri)


def authorize_domain(domain, header, thumb, akey, directory):
    resp = make_request(directory["newOrder"],
                        header,
                        {
                            "identifiers": [{"type": "dns", "value": domain}],
                        },
                        akey,
                        directory)
    if resp.status_code != 201:
        print(resp.text)
        raise Exception("Error fetching challenges: {0} {1}".format(resp.status_code, resp.reason))
    order = resp.json()
    pprint(order)
    status, token, uri = http01_challenge(order, directory)
    print(status, token, uri)
    if status == "valid":
        logging.getLogger(__name__).info("Domain %s already verified" % domain)
        return order

    key = token + "." + thumb

    # push to fus
    requests.get("http://%s/.well-known/acme-challenge/upload/%s/%s" % (domain, token, thumb))
    wait_for_auth_file(domain, token, key)

    resp = make_request(uri,
                        header,
                        dict(),
                        akey,
                        directory)
    if resp.status_code not in [200, 201, 202, 204]:
        raise Exception("Error notifying server: {0} {1}".format(resp.status_code, resp.reason))

    wait_for_verification(uri)
    logging.getLogger(__name__).info("Domain %s verified" % domain)
    return order


def fetch_certificate(finalize_url, domain, domain_key, header, akey, directory):
    csr = get_csr(domain, domain_key)
    resp = make_request(finalize_url,
                        header,
                        {
                            "csr": csr,
                        },
                        akey,
                        directory)
    if resp.status_code not in [200, 201, 202, 204]:
        raise Exception("Error fetching signed certificate for %s: %s %s"
                        % (domain, resp.status_code, resp.reason))

    return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, resp.content)


def unpack_cert(target):
    if isinstance(target, str):
        return target, target
    else:
        return target


def needs_update(targets):

    for target in targets:
        crt_name, _ = unpack_cert(target)
        if not os.access(crt_name, os.R_OK):
            logging.getLogger(__name__).warning("Cert %s missing, update required" % crt_name)
            return True
        with open(crt_name) as f:
            crt = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, f.read())
            dt = dateutil.parser.parse(crt.get_notAfter())
            valid_seconds = (dt - datetime.datetime.now(pytz.utc)).total_seconds()
            if valid_seconds < 86400 * MIN_CERT_VALIDITY_DAYS:
                logging.getLogger(__name__).warning(
                    "Cert %s valid for only %d days" % (crt_name, int(valid_seconds / 86400)))
                return True
            else:
                logging.getLogger(__name__).info(
                    "Cert %s valid for %d days" % (crt_name, int(valid_seconds / 86400)))
    return False


def install_cert(cert, key, targets):
    for target in targets:
        cert_name, key_name = unpack_cert(target)

        now = datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)
        date_str = now.strftime("%F_%T")

        if os.access(key_name, os.R_OK):
            os.rename(key_name, key_name + date_str)

        if os.access(cert_name, os.R_OK):
            os.rename(cert_name, cert_name + date_str)

        with open(cert_name, "wb") as f:
            f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
            f.write(b"\n")
            f.write(INTERMEDIATE_CERT)
        with open(key_name, "ab") as f:
            f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))


def restart_service(service, manager):
    logging.getLogger(__name__).info("Restarting service %s" % service)
    manager.TryRestartUnit(service, "fail")


def restart_services(services):
    sysbus = dbus.SystemBus()
    systemd1 = sysbus.get_object('org.freedesktop.systemd1', '/org/freedesktop/systemd1')
    manager = dbus.Interface(systemd1, 'org.freedesktop.systemd1.Manager')
    jobs = manager.ListUnits()

    for service in services:
        if not service.endswith(".service"):
            service = service + ".service"
        for j in jobs:
            if j[0] != service:
                continue
            if j[3] != "active":
                logging.getLogger(__name__).warning("Service %s not running, ignored" % service)
                continue

            restart_service(service, manager)


# swith to working directory
os.chdir(os.path.dirname(os.path.abspath(__file__)))

for cert, key in LOCATIONS:
    os.system("scp %s root@pi:%s" % (key, key))
    os.system("scp %s root@pi:%s" % (cert, cert))

if needs_update(LOCATIONS):

    akey = get_private_key(ACCOUNT_KEY)
    dkey = get_private_key(DOMAIN_KEY)
    header = get_header(akey)
    account_thumb = get_account_print(header)

    directory = get_directory()
    account, acct_header = sign_in(header, akey, directory)

    header.pop("jwk", None)
    header["kid"] = acct_header["location"]

    order = authorize_domain(DOMAIN,
                             header,
                             account_thumb,
                             akey,
                             directory)

    cert = fetch_certificate(order["finalize"],
                             DOMAIN,
                             dkey,
                             header,
                             akey,
                             directory)

    install_cert(cert, dkey, LOCATIONS)

    restart_services(SERVICES)
