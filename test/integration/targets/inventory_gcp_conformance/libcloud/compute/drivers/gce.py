class Connection(object):
    def __init__(self, key, secure=True, host=None, port=None, url=None,
            timeout=None, proxy_url=None, backoff=None, retry_delay=None):
        self.key = key
        self.secure = secure
        self.host = host
        self.port = port
        self.url = url
        self.timeout = timeout
        self.proxy_url = proxy_url
        self.backoff = backoff
        self.retry_delay = retry_delay

        self.ua = []

    def user_agent_append(self, token):
        self.ua.append(token)

class GCENodeDriver(object):
    def __init__(self, user_id, key=None, datacenter=None, project=None,
            auth_type=None, scopes=None, credential_file=None, **kwargs):
        self.user_id = user_id
        self.key = key
        self.datacenter = datacenter
        self.project = project
        self.auth_type = auth_type
        self.scopes = scopes
        self.credential_file = credential_file
        self.connection = Connection('gce')

