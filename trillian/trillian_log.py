import base64
import json
import io
import logging
import requests
import struct

from collections import namedtuple

import utcdatetime

from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

LOG = logging.getLogger(__name__)

LogRoot = namedtuple('LogRoot', 'tree_size,root_hash,timestamp_nanos')


class LogRootDecoder():
    """
    log_root holds the TLS-serialization of the following structure (described
    in RFC5246 notation): Clients should validate log_root_signature with
    VerifySignedLogRoot before deserializing log_root.

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
    def __init__(self, log_root_bytes):
        self._data = log_root_bytes

    def __str__(self):

        return str(self.log_root)

    def __repr__(self):
        return self.__str__()

    def decode(self):
        s = io.BytesIO(self._data)

        self._decode_version(s),

        tree_size = self._decode_tree_size(s)
        root_hash = self._decode_root_hash(s)
        timestamp_nanos = self._decode_timestamp_nanos(s)

        self._decode_revision(s)
        self._decode_metadata(s)

        self.log_root = LogRoot(
            tree_size=tree_size,
            root_hash=root_hash,
            timestamp_nanos=timestamp_nanos
        )

        leftover = len(s.read())
        assert leftover == 0, '{} bytes leftover'.format(leftover)
        return self.log_root

    @staticmethod
    def _decode_version(s):
        result, = struct.unpack('>H', LogRootDecoder._read_n_bytes(s, 2))
        assert result == 1
        return result

    @staticmethod
    def _decode_tree_size(s):
        return LogRootDecoder._decode_uint64(s)

    @staticmethod
    def _decode_root_hash(s):
        length_prefix = LogRootDecoder._read_n_bytes(s, 1)
        length, = struct.unpack(">B", length_prefix)
        assert length == 32, 'Expected 32-byte hash, got {}'.format(length)

        return LogRootDecoder.to_b64(
            LogRootDecoder._read_n_bytes(s, length)
        )

    @staticmethod
    def _decode_timestamp_nanos(s):
        return LogRootDecoder._decode_uint64(s)

    @staticmethod
    def _decode_revision(s):
        return LogRootDecoder._decode_uint64(s)

    @staticmethod
    def _decode_metadata(s):
        length_prefix = LogRootDecoder._read_n_bytes(s, 2)
        length, = struct.unpack(">H", length_prefix)

        return LogRootDecoder._read_n_bytes(s, length)

    @staticmethod
    def _decode_uint64(s):
        # https://docs.python.org/3/library/struct.html#format-characters
        # Q = uint64
        result, = struct.unpack('>Q', LogRootDecoder._read_n_bytes(s, 8))
        return result

    @staticmethod
    def _read_n_bytes(s, n):
        result = s.read(n)
        assert len(result) == n
        return result

    @staticmethod
    def to_b64(binary):
        return base64.b64encode(binary).decode('ascii')


class LogEntry():
    def __init__(self, raw_data):
        if not isinstance(raw_data, bytes):
            raise ValueError('raw_data: expected bytes, got {}'.format(
                type(raw_data)
            ))
        self.__raw_data = raw_data

    def json(self):
        return json.loads(self.__raw_data.decode('utf-8'))


class TrillianLog():
    """
    Stub!
    """

    def __init__(self, base_url, public_key):
        if not base_url:
            raise ValueError(
                'Must provide a `base_url` of the form '
                'http://<host>:<port>/v1beta1/logs/<log_id>'
            )

        self.__url = base_url
        self.__public_key_algo = None
        self.__hash_algo = None
        self.__public_key_der = None

        self._parse_public_key(public_key)

    def get_log_root(self):
        return self.validate_signed_log_root(
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

            return LogEntry(
                raw_data=base64.b64decode(latest_entry['leaf_value'])
            )

    def append(self, entry):
        assert isinstance(entry, dict), \
            'expecting a dict, got: `{}`'.format(entry)
        LOG.info('Appending to log: {}'.format(entry))

        response = requests.post(
            '{}/leaves'.format(self.__url),
            json=entry
        )
        response.raise_for_status()

    def get_leaves_by_range(self, start_index, count):
        return self._get(
            '/leaves:by_range',
            {
                'start_index': start_index,
                'count': count
            }
        ).json()['leaves']

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

    def validate_signed_log_root(self, signed_log_root):
        try:
            self.validate_signature(
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
            LOG.info('Signature is valid')
            return d

    def validate_signature(self, log_root, log_root_signature, public_key):
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
