from datetime import date
import requests
import ed25519
import hashlib
import base64
import inspect
import json
import base64
import sys
import os
import re

# Offline caching system
class OfflineCache:

  @staticmethod
  def write(res):
    body      = res.text
    signature = res.headers['Keygen-Signature']
    digest    = res.headers['Digest']
    date      = res.headers['Date']

    cache_key  = OfflineCache.__cache_key()
    cache_data = inspect.cleandoc(
      """
      {signature}
      {digest}
      {date}
      {body}
      """
    ).format(
      signature=signature,
      digest=digest,
      date=date,
      body=body
    )

    with open('cache/{}.dat'.format(cache_key), 'w') as f:
      f.write(cache_data)

  @staticmethod
  def read():
    cache_key = OfflineCache.__cache_key()
    data = None

    try:
      with open('cache/{}.dat'.format(cache_key), 'r') as f:
        data = f.read()
    except:
      pass

    return data.split('\n')

  # Cache key is day+month+year of current datetime. This will cache
  # the data for the current day. You can change the cache key to adjust
  # the cache TTL, e.g. "30-ish days" could be month+year, which will
  # rotate the cache on the 1st of every month. You may also want to
  # clean up old cache keys, to prevent an evergrowing cache.
  @staticmethod
  def __cache_key():
    return date.today().strftime('%d%m%Y')

# Cryptographically verify the response signature using the provided verify key
def verify_response_signature(sig_header, digest_header, date_header, response_body):
  assert sig_header, 'response signature header is missing'
  assert digest_header, 'response digest is missing'
  assert date_header, 'response date is missing'
  assert response_body, 'response body is missing'

  # Parse the signature header into a dict
  sig_params = dict(
    map(
      lambda param: re.match('([^=]+)="([^"]+)"', param).group(1, 2),
      re.split(',\s*', sig_header)
    )
  )

  # Reconstruct the signing data
  digest_bytes = base64.b64encode(hashlib.sha256(response_body.encode()).digest())
  signing_data = inspect.cleandoc(
    """
    (request-target): post /v1/accounts/{account_id}/licenses/actions/validate-key
    host: api.keygen.sh
    date: {date}
    digest: sha-256={digest}
    """.format(
      account_id=os.environ['KEYGEN_ACCOUNT_ID'],
      date=date_header,
      digest=digest_bytes.decode()
    )
  )

  # Load the hex formatted verify key from the environment
  verify_key = ed25519.VerifyingKey(os.environ['KEYGEN_VERIFY_KEY'].encode(), encoding='hex')

  # Verify the response signature
  try:
    verify_key.verify(sig_params['signature'], signing_data.encode(), encoding='base64')

    return True
  except ed25519.BadSignatureError:
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

    return data['meta']['valid'], data['meta']['code'], data['meta']['ts'], is_online

  # This error likely means that we are offline. We could verify further
  # by pinging https://google.com, or https://api.keygen.sh/v1/ping.
  except requests.exceptions.ConnectionError:
    # Read the offline cache (if any data exists)
    cache_data = OfflineCache.read()
    if cache_data != None:
      sig, digest, date, body = cache_data

      # Verify the cached data
      ok = verify_response_signature(sig, digest, date, body)
      if ok:
        # Respond with the cached data
        data = json.loads(body)

        # At this point, you could check `date` to see when the license was last validated
        # and compare to the system time, e.g. if you wanted to allow the cached validation
        # to "pass" for 30 days.

        return data['meta']['valid'], data['meta']['code'], data['meta']['ts'], is_online

    return False, None, None, is_online

# Run from the command line:
#   python main.py some_license_key
is_valid, validation_code, last_validated_at, is_online = validate_license_key(sys.argv[1])

print(
  'is_valid={} validation_code={} last_validated_at={} is_online={}'.format(
    is_valid,
    validation_code,
    last_validated_at,
    is_online
  )
)
