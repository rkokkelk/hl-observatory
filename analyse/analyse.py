import hashlib
import requests
import ssl, socket
import logging

from threading import Thread

"""
Functionality which verifies the SSL connection with different procedures

The following details are requested with each connection
  - SSL/TLS version
  - Cert fingerprint
  - Certificate Chain
  - TLS Cipher modes
"""

log = logging.getLogger("Observatory.ssl")

# Configure SSL Context
context = ssl.SSLContext(ssl.PROTOCOL_SSLv23) # No support for SSLv2
#context.options |= ssl.PROTOCOL_SSLv2        Todo: option is needed to enable SSLv2, 
#                                             however is only avalable if openssl is compiled without OPENSSL_NO_SSL2 flag
context.verify_mode = ssl.CERT_OPTIONAL
context.check_hostname = True
context.load_default_certs()

# Socket timeout in seconds
socket.setdefaulttimeout(30)

def analyse_ssl(domain):
    result = dict()
    dst = "https://{0}".format(domain)

    # Verify if URL redirects, if so, use redirect
    (redirect, new_dst) = verify_redirect(dst)
    dst = new_dst if redirect else dst

    log.debug("SSL Analyze %s", dst)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_socket = context.wrap_socket(s, server_hostname=domain)
    ssl_socket.connect((domain, 443))

    cert = ssl_socket.getpeercert(False)
    bin_cert = ssl_socket.getpeercert(True)
    ciphers = ssl_socket.cipher()

    sha1sum = hashlib.sha1(bin_cert).hexdigest()
    sha256sum = hashlib.sha256(bin_cert).hexdigest()

    result['sha1'] = sha1sum
    result['sha256'] = sha256sum
    result['ciphers'] = ciphers

    log.debug("[%s] Cert: %s", domain, cert['subject'])
    log.debug("[%s] Fingerprint (SHA1): %s", domain, sha1sum)
    log.debug("[%s] Fingerprint (SHA256): %s", domain, sha256sum)
    log.debug("[%s] Ciphers: %s", domain, ciphers)

    return result

def analyse_dns(domain):
    log.debug("DNS Analyze %s", domain)

    # Get DNS info and retrieve IPv4/IPv6 addresses
    dns = socket.getaddrinfo(domain, 443)
    results = [record[4][0] for record in dns]
    results = list(set(results)) # Some records are the same, set removes duplicated, return to list to make iterable

    if len(results) == 0:
        raise Exception('No DNS resolving')

    return results

def analyse_domain(domain):
    result = dict()
    try:
        result['dns'] = analyse_dns(domain)
        result['ssl'] = analyse_ssl(domain)
    except Exception as e:
        message = str(e)
        log.error('[%s] %s', domain, message)
        result['error'] = message
    return result

def run(tid, domain_queue, result_queue):
     log.debug('Starting thread [%d]', tid)
     while not domain_queue.empty():
         domain = domain_queue.get()
         result = analyse_domain(domain)
         result_queue.put((domain,result))
         domain_queue.task_done()

def verify_redirect(dst):
    #Todo: set correct user-agent
    r = requests.get(dst)

    if r.status_code == 301:
        new_dst = r.headers['Location']
        log.warning('[%s] Redirection to: %s', dst, new_dst)

        if not new_dst.startswith('https'):
            raise Exception('Redirected to HTTP connection: '+new_dst)

        return (True, new_dst)
    elif r.status_code == 200:
        return (False, '')
    else:
        raise Exception('Unknown status code returned: '+str(r.status_code))

def tls_server_callback(socket, dst, context):
    log.debug("TLS connecting to %s",dst)
