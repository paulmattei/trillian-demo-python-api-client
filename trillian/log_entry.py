import json

from .helpers import from_b64


class LogEntry():
    def __init__(self, leaf_index, leaf_value, queue_timestamp,
                 integrate_timestamp, leaf_identity_hash, merkle_leaf_hash,
                 extra_data):

        if not isinstance(leaf_value, str):
            raise ValueError('leaf_value: expected base64 str, got {}'.format(
                type(leaf_value)
            ))

        self.leaf_value = from_b64(leaf_value)
        self.leaf_index = leaf_index
        self.queue_timestamp = queue_timestamp
        self.integrate_timestamp = integrate_timestamp
        self.leaf_identity_hash = leaf_identity_hash
        self.merkle_leaf_hash = merkle_leaf_hash

    def __str__(self):
        return 'LogEntry(idx={} data={})'.format(
            self.leaf_index, str(self.leaf_value)
        )

    def __repr__(self):
        return self.__str__()

    def json(self):
        return json.loads(self.leaf_value.decode('utf-8'))
