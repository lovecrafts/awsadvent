"""
Service helper to validate AWS ALB added JWT tokens.
Used in a lua subrequest by nginx to provide X-Auth- headers
"""
import os
import jwt
import json
import base64
import requests
import logging
from functools import lru_cache
from logging import Logger, Formatter
from logging.handlers import RotatingFileHandler
from statsd import StatsClient

"""
Initialise logging and monitoring
"""
statsd = StatsClient(prefix='awsjwtauth')
log = Logger(name='awsjwtauth')
handler = RotatingFileHandler(
    os.environ.get('LOGFILE', 'awsjwtauth.log'),
    maxBytes=os.environ.get('LOGMAXSIZE', 10485760),
    backupCount=os.environ.get('LOGKEEP', 7),
    )
formatter = Formatter(
    '{"@timestamp":"%(asctime)s", "level":"%(levelname)s", '
    '"message":"%(message)s", "lc-rid":"%(RID)s", "lc-sid":"%(SID)s"}'
)
handler.setFormatter(formatter)
LOG_LEVEL = getattr(logging, os.environ.get('LOG_LEVEL', 'warn').upper())
handler.setLevel(LOG_LEVEL)
log.addHandler(handler)
SID = '-'
RID = '-'
log.debug('Starting Worker', extra={'SID': SID, 'RID': RID})

REGION = os.environ.get('REGION', 'eu-west-1')


@statsd.timer('validate_jwt')
def is_valid(encoded_jwt):
    """
    Validate the JWT Token

    :param awsjwt: JWT Object
    :type awsjwt: awsjwt

    :return: True if a valid JWT token otherwise false
    :rtype: boolean
    """
    if encoded_jwt is None:
        statsd.incr('info.no_header')
        log.error('No JWT Header present', extra={'SID': SID, 'RID': RID})
        return False
    kid = get_kid(encoded_jwt)
    pub_key = get_key(REGION, kid)
    try:
        payload = jwt.decode(encoded_jwt, pub_key, algorithms=['ES256'])
    except jwt.InvalidTokenError as e:
        statsd.incr('error.validation.jwt_failed')
        log.error('Error Validating JWT Header: {0}'.format(e),
                  extra={'SID': SID, 'RID': RID})
        return (False, None)
    except TypeError as e:
        statsd.incr('error.validation.typeerror')
        log.error('Error Validating JWT Header: {0}'.format(e),
                  extra={'SID': SID, 'RID': RID})
        log.debug('Flushing keys caches', extra={'SID': SID, 'RID': RID})
        statsd.incr('cache.keys.flush')
        get_key.cache_clear()
        return (False, None)
    return (True, payload)


@lru_cache(maxsize=32)
@statsd.timer('get_pub_key')
def get_key(region, kid):
    """
    Fetch the public key for the JWT signature from AWS key servers.
    This is the only external dependency for this script, so we time it

    :param kid: Key ID to be used for validating signature
    :type kid: string

    :return: Public Key string
    :rtype: string
    """
    try:
        url = 'https://public-keys.auth.elb.{r}.amazonaws.com/{k}'.format(
            r=region, k=kid)
        log.debug('Fetching Key: {0}'.format(url),
                  extra={'SID': SID, 'RID': RID})
        req = requests.get(url, timeout=0.5)
        return req.text
    except requests.exceptions.Timeout:
        statsd.incr('error.pub_key.timeout')
        log.error('Timed out connecting to public key server',
                  extra={'SID': SID, 'RID': RID})
    except requests.exceptions.ConnectionError:
        statsd.incr('error.pub_key.connect')
        log.error('Unable to connect to public key server',
                  extra={'SID': SID, 'RID': RID})


def get_kid(encoded_jwt):
    """
    Extract the Key ID from the JWT Token
    Header is base64 encoded JSON strings
    <jwt_info>.<profile_data>.<signature>

    :return: key id extracted from header
    :rtype: string
    """
    try:
        jwt_headers = encoded_jwt.split('.')[0]
        decoded_jwt_headers = base64.b64decode(jwt_headers)
        decoded_json = json.loads(decoded_jwt_headers)
        return decoded_json['kid']
    except KeyError:
        statsd.incr('error.validate.missing_kid')
        log.error('Missing kid in decoded json jwt',
                  extra={'SID': SID, 'RID': RID})


class awsjwt(object):

    def __init__(self, request):
        self.encoded_jwt = request.get('HTTP_X_AMZN_OIDC_DATA')
        self.valid_domains = request.get('HTTP_X_LC_VALID_DOMAINS', '')
        self.sid = request.get('HTTP_X_LC_SID', '-')
        self.rid = request.get('HTTP_X_LC_RID', '-')
        self.payload = None
        self.kid = None

    def get_request_ids(self):
        """
        """
        return (self.sid, self.rid)

    def valid_email(self):
        """
        Check that the email address of the user in the payload is in the list
        of authorised domains provided by the upstream.
        """
        log.debug('Valid domains: {0}'.format(self.valid_domains),
                  extra={'SID': SID, 'RID': RID})
        domains = self.valid_domains.split(',')
        email = self.payload.get('email')
        log.debug('Payload email: {0}'.format(email),
                  extra={'SID': SID, 'RID': RID})
        if email is None:
            statsd.incr('error.validate.missing_email')
            log.error('No email in payload', extra={'SID': SID, 'RID': RID})
            return False
        domain = email.split('@')[1]
        if domain in domains:
            statsd.incr('info.auth_user')
            return True
        else:
            statsd.incr('info.unauth_user')
            log.warn('Unauthorised access by: {0}'.format(email),
                     extra={'SID': SID, 'RID': RID})
            return False


@statsd.timer('request')
def app(environ, start_response):
    """
    Main request function called by gunicorn

    :param environ: request object from gunicorn
    :type environ: dict

    :param start_response: response function
    :type start_response: method
    """
    global SID, RID

    jwt = awsjwt(environ)
    (SID, RID) = jwt.get_request_ids()
    log.debug('Starting request', extra={'SID': SID, 'RID': RID})

    status = '200 OK'
    response_headers = []
    data = b'OK'
    (valid, jwt.payload) = is_valid(jwt.encoded_jwt)
    if not valid:
        status = '401'
        data = b'Invalid or missing JWT Token'
    else:
        if not jwt.valid_email():
            status = '403'
            data = b'No valid email domain'
        else:
            response_headers.append(
                ('X-Auth-Email', jwt.payload.get('email')))
            response_headers.append(
                ('X-Auth-Given-name', jwt.payload.get('given_name')))
            response_headers.append(
                ('X-Auth-Family-name', jwt.payload.get('family_name')))
            response_headers.append(
                ('X-Auth-Picture', jwt.payload.get('picture')))

    # pylint: disable=E1120
    statsd.gauge('cache.keys.hits', get_key.cache_info().hits)
    statsd.gauge('cache.keys.misses', get_key.cache_info().misses)
    statsd.gauge('cache.keys.size', get_key.cache_info().currsize)
    statsd.gauge('cache.keys.limit', get_key.cache_info().maxsize)
    response_headers.append(('Content-type', 'text/plain'))
    response_headers.append(('Content-Length', str(len(data))))

    start_response(status, response_headers)
    return iter([data])
