# Trillian Demo: Python API client library

This library helps you interact with a Trillian log. It provides a `TrillianLog` class with methods like `.append()`.

## Install

You'll need to clone this repository and install it manually in your Python app. For example:

```
. venv/bin/activate
pip install -e ~/trillian-demo-python-api-client/
```

## Usage

### Example use

```
python
>>> log = TrillianLog.load_from_environment()
>>> log.append({'foo': 'bar'})
>>> log.latest()
LogEntry(idx=14, data=b'{\n"foo": "bar"\n}')

>>> log.latest().json()
{'foo': 'bar'}
```

### `TrillianLog.load_from_environment()`

Helper: reads `TRILLIAN_LOG_URL` and `TRILLIAN_LOG_PUBLIC_KEY` from the environment and
instantiates a `TrillianLog` class.

### `TrillianLog(log_url, public_key)`

Instantiate a `TrillianLog` class with the `log_url` of a log, for example:

- `log_url`: `https://trillian.example.com/v1beta1/logs/472384632756347`
- `public_key`: `ECDSA:SHA256:MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAER4Z5Ac9QEtvFqz7c808DJP1IzqxN88r8aUNsC2pluKHkw5EK+vQ1DKaSG20zufLlIeDvWNEYZ6INgqm7Fz35Nw==`

### `.get_log_root()`

Gets the signed log root, validates the signature against the public key

```
python
>>> log.get_log_root()
LogRoot(tree_size=5, root_hash='F/ZKT9N6eoDQi0+paj3eToI/U9xu1ZriSMy/vhjkm30=', timestamp_nanos=1531403868624765390)
```

### `.append(dictionary)`

Insert a Python dictionary into the Trillian log.

```
python
>>> log.append({'foo': 'bar'})
```

### `.latest()`

Find the latest leaf (log entry) in the Trillian log and return it as a `LogEntry` object.

```
python
>>> log.latest()
LogEntry(idx=14, data=b'{\n"foo": "bar"\n}')
```

### `.full_audit(log_root)`

Download and hash all the data in the log, recreating a Merkle tree and comparing its root hash against the given `log_root`.

```
python
>>> log.full_audit(log.get_log_root())
True
```

### `.get_leaves_by_range(start_index, count)`

Download the given leaves from the log as `LogEntry` objects.

```
python
>>> log.get_leaves_by_range(0, 2)
[LogEntry(idx=0 data=b'{\n"datetime": "2018-07-12T00:00:00Z",\n"Eastbridge Road - Pedestrians": "23",\n"Eastbridge Road - Bicycles": "15",\n"Eastbridge Road - Cars": "45"\n}'),
 LogEntry(idx=1 data=b'{\n"datetime": "2018-07-12T01:00:00Z",\n"Eastbridge Road - Pedestrians": "34",\n"Eastbridge Road - Bicycles": "4",\n"Eastbridge Road - Cars": "34"\n}')]
```
