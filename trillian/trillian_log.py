import base64
import logging
import os
import requests

from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

from .dict_to_base64_normaliser import DictToBase64Normaliser
from .helpers import to_b64
from .log_root_decoder import LogRootDecoder
from .log_entry import LogEntry
from .merkle import TreeHasher
from . import error

LOG = logging.getLogger(__name__)


class TrillianLog():

    def __init__(self, log_url, public_key):
        if not log_url:
            raise ValueError(
                'Must provide a `log_url` of the form '
                'http://<host>:<port>/v1beta1/logs/<log_id>'
            )

        self.__url = log_url
        self.__public_key_algo = None
        self.__hash_algo = None
        self.__public_key_der = None

        self._parse_public_key(public_key)

    @classmethod
    def load_from_environment(cls):
        url = os.environ.get('TRILLIAN_LOG_URL', None)
        if not url:
            raise RuntimeError(
                'No TRILLIAN_LOG_URL found in `settings.sh`. It should look like '
                'http://<host>:<post>/v1beta1/logs/<log_id>. On the demo log '
                'server, see http://192.168.99.4:5000/demoapi/logs/ to '
                'and look for the `log_url` field'
            )

        public_key = os.environ.get('TRILLIAN_LOG_PUBLIC_KEY', None)

        if not public_key:
            raise RuntimeError(
                'No TRILLIAN_LOG_PUBLIC_KEY found in `settings.sh`. On the demo '
                'log server, see http://192.168.99.4:5000/demoapi/logs/ to '
                'and look for the `public_key` field'
            )

        return cls(url, public_key)

    def get_log_root(self):
        return self._validate_signed_log_root(
            self._get('/roots:latest').json()
        )

    def latest(self):
        validated_log_root = self.get_log_root()
        LOG.debug(validated_log_root)
        tree_size = validated_log_root.tree_size

        if tree_size == 0:
            return None

        else:
            latest_entry = self.get_leaves_by_range(tree_size-1, 1)[0]

            return latest_entry

    def append(self, dictionary):
        """
        Insert a Python dictionary as a log entry.

        This method normalizes the dictionary to binary, encodes it as base64
        and pushes it to the API.
        """
        assert isinstance(dictionary, dict), \
            'expecting dict, got: {}: `{}`'.format(
                type(dictionary), dictionary)
        LOG.debug('Appending to log: {}'.format(dictionary))

        normaliser = DictToBase64Normaliser(dictionary)

        response = requests.post(
            '{}/leaves'.format(self.__url),
            json={'base64_data': normaliser.normalise()}
        )
        response.raise_for_status()

    def get_leaves_by_range(self, start_index, count):
        def to_log_entry(leaf):
            return LogEntry(**leaf)

        return list(map(
            to_log_entry,
            self._get(
                '/leaves:by_range',
                {
                    'start_index': start_index,
                    'count': count
                }
            ).json()['leaves']
        ))

    def full_audit(self, log_root):
        """
        Download all leaves, build a Merkle Tree and calculate the root hash.
        """

        def to_binary_leaf_data(log_entry):
            return log_entry.leaf_value

        tree_size = log_root.tree_size

        leaves = list(map(
            to_binary_leaf_data,
            self.get_leaves_by_range(0, tree_size)
        ))

        LOG.debug('Generating Merkle tree root hash for {} leaves'.format(
            len(leaves)))

        calculated_root_hash = to_b64(TreeHasher().hash_full_tree(leaves))

        if log_root.root_hash == calculated_root_hash:
            return True
        else:
            raise error.ConsistencyError(
                'Signed log root hash `{}` != calculated hash `{}`'.format(
                    log_root.root_hash, calculated_root_hash
                ))

    def _get(self, url_path, params=None):
        params = params or {}
        full_url = '{}{}'.format(self.__url, url_path)

        try:
            response = requests.get(full_url, params=params)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            logging.exception(e)
            raise
        else:
            return response

    def _parse_public_key(self, colon_separated_key):
        (
            self.__public_key_algo,
            self.__hash_algo,
            self.__public_key_der
        ) = colon_separated_key.split(':')

    def _validate_signed_log_root(self, signed_log_root):
        try:
            self._validate_signature(
                base64.b64decode(signed_log_root['log_root']),
                base64.b64decode(signed_log_root['log_root_signature']),
                self.__public_key_der
            )
        except ValueError:
            LOG.error('Signature is invalid')
            raise
        else:
            d = LogRootDecoder(
                base64.b64decode(signed_log_root['log_root'])
            ).decode()
            LOG.debug('Signature is valid')
            return d

    @staticmethod
    def _validate_signature(log_root, log_root_signature, public_key):
        """
        log_root holds the TLS-serialization of the following structure
        (described # in RFC5246 notation): Clients should validate
        log_root_signature with # VerifySignedLogRoot before deserializing
        log_root.
        enum { v1(1), (65535)} Version;
        struct {
          uint64 tree_size;
          opaque root_hash<0..128>;
          uint64 timestamp_nanos;
          uint64 revision;
          opaque metadata<0..65535>;
        } LogRootV1;
        struct {
          Version version;
          select(version) {
            case v1: LogRootV1;
          }
        } LogRoot;
        """

        key = ECC.import_key(base64.b64decode(public_key))
        logging.debug('Loaded public key: {}'.format(key))

        verifier = DSS.new(key, 'fips-186-3', encoding='der')

        data_to_hash = log_root
        hash_object = SHA256.new(data_to_hash)

        try:
            verifier.verify(hash_object, log_root_signature)
        except ValueError as e:
            raise
