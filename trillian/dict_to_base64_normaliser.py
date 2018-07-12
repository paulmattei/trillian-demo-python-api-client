import json

from collections import OrderedDict

from .helpers import to_b64


class DictToBase64Normaliser():
    def __init__(self, dictionary):
        self.__dictionary = dictionary

    def normalise(self):
        """
        Normalise a python dictionary, encode it as JSON return it base64
        encoded.
        """
        self._validate_is_dictionary()
        self._validate_not_empty()
        self._stringify_numbers()
        self._order_by_keys()

        return to_b64(self._encode_to_json())

    def _validate_is_dictionary(self):
        pass

    def _validate_not_empty(self):
        pass

    def _stringify_numbers(self):
        self.__dictionary = {k: str(v) for k, v in self.__dictionary.items()}

    def _order_by_keys(self):
        self.__dictionary = OrderedDict(
            sorted(self.__dictionary.items(), key=lambda x: x[0], reverse=True)
        )

    def _encode_to_json(self):

        return json.dumps(self.__dictionary, indent=0).encode('utf-8')
