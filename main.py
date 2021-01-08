from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from datetime import date
import requests
import json
import base64
import sys
import os

# Offline caching system
class OfflineCache:

  @staticmethod
  def write(res):
    cache_key = OfflineCache.__cache_key()
    body = res.text
    sig = res.headers['X-Signature']

    with open('cache/{}.json'.format(cache_key), 'w') as f:
      f.write(body)

    with open('cache/{}.sig'.format(cache_key), 'w') as f:
      f.write(sig)

  @staticmethod
  def read():
    cache_key = OfflineCache.__cache_key()
    body = None
    sig = None

    try:
      with open('cache/{}.json'.format(cache_key), 'r') as f:
        body = f.read()
    except:
      pass

    try:
      with open('cache/{}.sig'.format(cache_key), 'r') as f:
        sig = f.read()
    except:
      pass

    return body, sig

  # Cache key is day+month+year of current datetime. This will cache
  # the data for the current day. You can change the cache key to adjust
  # the cache TTL, e.g. "30-ish days" could be month+year, which will
  # rotate the cache on the 1st of every month. You may also want to
  # clean up old cache keys, to prevent an evergrowing cache.
  @staticmethod
  def __cache_key():
    return date.today().strftime('%d%m%Y')

# Cryptographically verify the response signature using the provided public key
def verify_response_signature(body, sig):
  assert body, 'response body is missing'
  assert sig, 'signature is missing'

  # Load the PEM formatted public key from the environment
  pub_key = serialization.load_pem_public_key(
    bytes(os.environ['KEYGEN_PUBLIC_KEY'], encoding='ASCII'),
    backend=default_backend()
  )

  # Verify the response signature
  try:
    pub_key.verify(
      base64.b64decode(sig),
      bytes(body, encoding='UTF8'),
      padding.PKCS1v15(),
      hashes.SHA256()
    )

    return True
  except (InvalidSignature, TypeError):
    return False

# Validate the license key via the API or offline cache if present
def validate_license_key(key):
  is_online = False

  try:
    res = requests.post(
      'https://api.keygen.sh/v1/accounts/{}/licenses/actions/validate-key'.format(os.environ['KEYGEN_ACCOUNT_ID']),
      headers={
        'Content-Type': 'application/vnd.api+json',
        'Accept': 'application/vnd.api+json'
      },
      data=json.dumps({
        'meta': {
          'key': key
        }
      })
    )

    # Get the JSON response body
    data = res.json()

    # Request was successful, so we're online.
    is_online = True

    if 'errors' in data:
      code = None

      err = data['errors'][0]
      if 'code' in err:
        code = err['code']

      return False, code, None, is_online

    # Try to cache the successful response
    try:
      OfflineCache.write(res)
    except:
      pass

    return data['meta']['valid'], data['meta']['constant'], data['meta']['ts'], is_online

  # This error likely means that we are offline. We could verify further
  # by pinging https://google.com, or https://api.keygen.sh/v1/ping.
  except requests.exceptions.ConnectionError:
    # Read the offline cache (if any data exists)
    body, sig = OfflineCache.read()
    if body and sig:
      # Verify the cached data
      ok = verify_response_signature(body, sig)
      if ok:
        # Respond with the cached data
        data = json.loads(body)

        # At this point, you could check data['meta']['ts'] to see when the
        # license was last validated and compare to the system time, e.g. if
        # you wanted to allow the cached validation to "pass" for 30 days.

        return data['meta']['valid'], data['meta']['constant'], data['meta']['ts'], is_online

    return False, None, None, is_online

# Run from the command line:
#   python main.py some_license_key
valid, code, ts, is_online = validate_license_key(sys.argv[1])

print(
  'valid={} code={} time={} is_online={}'.format(valid, code, ts, is_online)
)