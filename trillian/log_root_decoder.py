import io
import struct

from collections import namedtuple
from .helpers import to_b64


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

        return to_b64(
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
