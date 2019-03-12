class Node(object):
    def __init__(self, id, name, state, public_ips, private_ips,
                 driver, size=None, image=None, extra=None, created_at=None):
        self.id = str(id) if id else None
        self.name = name
        self.state = state
        self.public_ips = public_ips if public_ips else []
        self.private_ips = private_ips if private_ips else []
        self.driver = driver
        self.size = size
        self.created_at = created_at
        self.image = image
        self.extra = extra or {}
        self.uuid = None

    def __repr__(self):
        state = NodeState.tostring(self.state)

        return (('<Node: uuid=%s, name=%s, state=%s, public_ips=%s, '
                 'private_ips=%s, provider=%s ...>')
                % (self.uuid, self.name, state, self.public_ips,
                   self.private_ips, self.driver.name))
