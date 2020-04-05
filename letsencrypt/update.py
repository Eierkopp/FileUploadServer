#!/usr/bin/python3

import base64
import binascii
import datetime
import dateutil.parser
import hashlib
import json
import logging
import os
import pytz
import requests
import subprocess
import time
import OpenSSL


SUCCESS_CODES = [200, 201, 202, 204]

logging.basicConfig(level=logging.DEBUG)


def b64(b):
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def enc_num(n):
    s = "%x" % n
    s = "0" * (len(s) % 2) + s
    return b64(binascii.unhexlify(s))


def get_private_key(fname):
    if os.access(fname, os.R_OK):
        with open(fname) as f:
            return OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, f.read())
    else:
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 4096)

        with open(fname, "wb") as f:
            f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))
        return key


def get_csr(domains, dkey):
    csr = OpenSSL.crypto.X509Req()
    csr.set_version(0)
    csr.set_pubkey(dkey)
    if len(domains) == 1:
        csr.get_subject().CN = domains[0]
    else:
        doms = ",".join("DNS:" + d for d in domains).encode("ascii")
        ext = OpenSSL.crypto.X509Extension(b"subjectAltName", False, doms)
        csr.add_extensions([ext])
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


def get_directory(dirname):
    response = requests.get(dirname)
    return response.json()


def sign_in(header, akey, directory):
    resp = make_request(directory["newAccount"],
                        header,
                        {
                            "termsOfServiceAgreed": True,
                        },
                        akey,
                        directory)
    if resp.status_code in SUCCESS_CODES:
        logging.getLogger(__name__).info("Account registered")
    elif resp.status_code == 409:
        logging.getLogger(__name__).info("Signed in to existing account")
    else:
        raise Exception("Failed to sign in: " + resp.reason + "\n" + resp.text)
    return resp.json(), resp.headers


def http01_challenge(auth_url, header, akey, directory):
    resp = make_request(auth_url,
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


def authorize_domain(domains, header, thumb, akey, directory):
    resp = make_request(directory["newOrder"],
                        header,
                        {
                            "identifiers": [{"type": "dns", "value": domain} for domain in domains],
                        },
                        akey,
                        directory)
    if resp.status_code not in SUCCESS_CODES:
        raise Exception("Error fetching challenges: {0} {1}".format(resp.status_code, resp.reason))
    order = resp.json()
    for i, url in enumerate(order["authorizations"]):
        domain = domains[i]
        status, token, finalize_url = http01_challenge(url, header, akey, directory)

        if status == "valid":
            logging.getLogger(__name__).info("Domain %s already verified" % domain)
            continue

        key = token + "." + thumb

        # push to fus
        requests.get("http://%s/.well-known/acme-challenge/upload/%s/%s" % (domain, token, thumb))
        wait_for_auth_file(domain, token, key)
        logging.getLogger(__name__).info("Notifying server for domain %s" % domain)
        resp = make_request(finalize_url,
                            header,
                            dict(),
                            akey,
                            directory)
        if resp.status_code not in SUCCESS_CODES:
            raise Exception("Error notifying server: {0} {1}".format(resp.status_code, resp.reason))

        wait_for_verification(finalize_url)
        logging.getLogger(__name__).info("Domain %s verified" % domain)
    return order


def fetch_certificate(finalize_url, domains, domain_key, header, akey, directory):
    logging.getLogger(__name__).info("Fetching certificate")
    csr = get_csr(domains, domain_key)
    resp = make_request(finalize_url,
                        header,
                        {
                            "csr": csr,
                        },
                        akey,
                        directory)
    if resp.status_code not in SUCCESS_CODES:
        raise Exception("Error fetching status for %s: %s %s"
                        % (domains, resp.status_code, resp.reason))
    status = resp.json()
    if status["status"] not in ["ready", "valid"]:
        raise Exception("Certificate not ready")

    resp = make_request(status["certificate"],
                        header,
                        None,
                        akey,
                        directory)
    if resp.status_code not in SUCCESS_CODES:
        raise Exception("Error fetching certificate for %s: %s %s"
                        % (domains, resp.status_code, resp.reason))

    return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, resp.content)


def needs_update(crt_name, min_validity):

    if not os.access(crt_name, os.R_OK):
        logging.getLogger(__name__).warning("Cert %s missing, update required" % crt_name)
        return True
    with open(crt_name) as f:
        crt = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, f.read())
        dt = dateutil.parser.parse(crt.get_notAfter())
        valid_seconds = (dt - datetime.datetime.now(pytz.utc)).total_seconds()
        if valid_seconds < 86400 * min_validity:
            logging.getLogger(__name__).warning(
                "Cert %s valid for only %d days" % (crt_name, int(valid_seconds / 86400)))
            return True
        else:
            logging.getLogger(__name__).info(
                "Cert %s valid for %d days" % (crt_name, int(valid_seconds / 86400)))
            return False


def install_cert(cert, key, cert_name, key_name, intermediate_name=None):
    now = datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)
    date_str = now.strftime("%F_%T")

    if os.access(key_name, os.R_OK):
        os.rename(key_name, key_name + date_str)

    if os.access(cert_name, os.R_OK):
        os.rename(cert_name, cert_name + date_str)

    if intermediate_name is not None:
        with open(intermediate_name, "rb") as f:
            chain = f.read()
    else:
        chain = b""

    with open(cert_name, "wb") as f:
        f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
        f.write(chain)

    with open(key_name, "wb") as f:
        f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))


def restart_service(service, manager):
    logging.getLogger(__name__).info("Restarting service %s" % service)
    manager.TryRestartUnit(service, "fail")


# swith to working directory
os.chdir(os.path.dirname(os.path.abspath(__file__)))

with open("config.json", encoding="utf-8") as f:
    config = json.load(f)

if needs_update(config["CRT_FILE"], config["MIN_CERT_VALIDITY_DAYS"]):

    akey = get_private_key(config["ACCOUNT_KEY"])
    dkey = get_private_key(config["DOMAIN_KEY"])
    header = get_header(akey)
    account_thumb = get_account_print(header)

    directory = get_directory(config["DEFAULT_DIRECTORY_URL"])
    account, acct_header = sign_in(header, akey, directory)

    header.pop("jwk", None)
    header["kid"] = acct_header["location"]

    order = authorize_domain(config["DOMAINS"],
                             header,
                             account_thumb,
                             akey,
                             directory)

    cert = fetch_certificate(order["finalize"],
                             config["DOMAINS"],
                             dkey,
                             header,
                             akey,
                             directory)

    install_cert(cert, dkey, config["CRT_FILE"], config["KEY_FILE"], config["INTERMEDIATE_CERTS"])

    for script in config["INSTALL_SCRIPTS"]:
        subprocess.check_call(script)
