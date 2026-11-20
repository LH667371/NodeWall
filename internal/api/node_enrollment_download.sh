CURL_HELP=$(curl --help all 2>&1 || true)
CURL_VERSION=$(curl --version 2>&1 || true)

join_download() {
  local url="$1" destination="$2"
  shift 2
  if [[ "$CURL_VERSION" == *'NSS/'* ]]; then
    local python
    python=$(command -v python3 || command -v python) || {
      echo '[nodewall] this legacy curl requires Python with TLS 1.2 support for pinned downloads' >&2
      return 1
    }
    # Older NSS cannot use the manager's self-signed leaf as a trust anchor.
    # Check the actual TLS peer before sending any HTTP headers or ticket.
    "$python" - "$JOIN_TMP/manager.crt" "$url" "$destination" "$@" <<'NODEWALL_HTTPS'
import shutil
import ssl
import sys

try:
    from http.client import HTTPSConnection
    from urllib.parse import urlsplit
except ImportError:
    from httplib import HTTPSConnection
    from urlparse import urlsplit

certificate, url, destination = sys.argv[1:4]
target = urlsplit(url)
if target.scheme != 'https' or not target.hostname or target.username is not None:
    sys.exit('NodeWall enrollment requires an HTTPS manager URL')
with open(certificate) as pem:
    end = '-----END CERTIFICATE-----'
    expected = ssl.PEM_cert_to_DER_cert(pem.read().split(end, 1)[0] + end + '\n')

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
connection = HTTPSConnection(target.hostname, target.port or 443, timeout=30, context=context)
try:
    connection.connect()
    if connection.sock.getpeercert(binary_form=True) != expected:
        sys.exit('NodeWall manager certificate pin mismatch')
    connection.auto_open = False
    headers = {}
    args = sys.argv[4:]
    for flag, header in zip(args[::2], args[1::2]):
        name, value = header.split(':', 1)
        if flag != '-H' or name.lower() not in ('authorization', 'x-nodewall-node-id'):
            sys.exit('Invalid NodeWall download header')
        headers[name] = value.strip()
    path = target.path or '/'
    if target.query:
        path += '?' + target.query
    connection.request('GET', path, headers=headers)
    response = connection.getresponse()
    if response.status != 200:
        sys.exit('NodeWall manager download returned HTTP %d' % response.status)
    with open(destination, 'wb') as output:
        shutil.copyfileobj(response, output, 1048576)
finally:
    connection.close()
NODEWALL_HTTPS
  elif [[ "$CURL_HELP" == *'--pinnedpubkey'* ]]; then
    curl -kfsS --connect-timeout 10 --max-time 300 --proto '=https' \
      --pinnedpubkey "$MANAGER_PIN" "$@" -o "$destination" "$url"
  else
    curl -fsS --connect-timeout 10 --max-time 300 --proto '=https' \
      --cacert "$JOIN_TMP/manager.crt" "$@" -o "$destination" "$url"
  fi
}
