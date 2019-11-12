import os
from functools import lru_cache

import psutil

import requests
import keyring
from ansible.plugins.vars import BaseVarsPlugin
from ansible.utils.display import Display
from ansible.utils.vars import combine_vars
from keepasshttplib import keepasshttplib, encrypter
from keepassxc_browser import Identity, Connection
from keepassxc_browser.protocol import ProtocolError


KEEPASSXC_CLIENT_ID = 'python-keepassxc-browser'
KEEPASSXC_PROCESS_NAMES = ['keepassxc', 'keepassxc.exe']
KEYRING_KEY = 'assoc'


display = Display()


class AnsibleKeepassError(Exception):
    body = 'Error in the Ansible Keepass plugin.'

    def __init__(self, msg=''):
        body = self.body
        if msg:
            body += ' {}'.format(msg)
        super().__init__(body)


class KeepassConnectionError(AnsibleKeepassError):
    body = 'Error on connection.'


class KeepassHTTPError(AnsibleKeepassError):
    body = ('The password for root could not be obtained using Keepass '
            'HTTP.')


class KeepassXCError(AnsibleKeepassError):
    body = ('The password for root could not be obtained using '
            'KeepassXC Browser.')


class KeepassBase:
    def get_password(self, host_name):
        raise NotImplementedError


class KeepassHTTP(KeepassBase):
    def __init__(self):
        super(KeepassHTTP, self).__init__()
        self.k = keepasshttplib.Keepasshttplib()

    @lru_cache(maxsize=None)
    def get_password(self, host_name):
        if not self.test_connection():
            raise KeepassHTTPError('Keepass is closed!')
        try:
            auth = self.k.get_credentials('ssh://{}'.format(host_name))
        except Exception as e:
            raise KeepassHTTPError(
                'Error obtaining host name {}: {}'.format(host_name, e)
            )
        if auth:
            return auth[1]
        return None

    def test_connection(self):
        key = self.k.get_key_from_keyring()
        if key is None:
            key = encrypter.generate_key()
        id_ = self.k.get_id_from_keyring()
        try:
            return self.k.test_associate(key, id_)
        except requests.exceptions.ConnectionError as e:
            raise KeepassHTTPError('Connection Error: {}'.format(e))


class KeepassXC(KeepassBase):
    _connection = None

    def __init__(self):
        super(KeepassXC, self).__init__()
        try:
            self.identity = self.get_identity()
        except Exception as e:
            raise KeepassConnectionError(
                'The identity could not be obtained from '
                'KeepassXC: {}'.format(e)
            )

    def get_identity(self):
        data = keyring.get_password(KEEPASSXC_CLIENT_ID, KEYRING_KEY)
        if data:
            identity = Identity.unserialize(KEEPASSXC_CLIENT_ID, data)
        else:
            identity = Identity(KEEPASSXC_CLIENT_ID)
        return identity

    def get_connection(self, identity):
        connection = Connection()
        connection.connect()
        connection.change_public_keys(identity)
        connection.get_database_hash(identity)

        if not connection.test_associate(identity):
            connection.associate(identity)

            if not connection.test_associate(identity):
                raise KeepassXCError(
                    'Association with KeePassXC failed.'
                )

            data = identity.serialize()
            keyring.set_password(KEEPASSXC_CLIENT_ID, KEYRING_KEY, data)

        return connection

    @property
    def connection(self):
        if self._connection is None:
            try:
                self._connection = self.get_connection(self.identity)
            except ProtocolError as e:
                raise AnsibleKeepassError(
                    'ProtocolError on connection: {}'.format(e)
                )
            except Exception as e:
                raise AnsibleKeepassError(
                    'Error on connection: {}'.format(e)
                )
        return self._connection

    @lru_cache(maxsize=None)
    def get_password(self, host_name):
        try:
            logins = self.connection.get_logins(
                self.identity,
                url='ssh://{}'.format(host_name)
            )
        except ProtocolError as e:
            # no logins found
            if str(e) == "No logins found":
                return None
            raise AnsibleKeepassError(
                'ProtocolError on connection: {}'.format(e)
            )
        except Exception as e:
            raise KeepassXCError(
                'Error obtaining host name {}: {}'.format(host_name, e)
            )
        if len(logins) > 1:
            raise KeepassXCError(
                'Error obtaining host name {}: '.format(host_name) +
                'multiple values returned'
            )
        return logins[0]['password']


class VarsModule(BaseVarsPlugin):
    """
    Loads variables from KeePassXC (either via KeePassHTTP or as
    browser plugin).
    """

    KEEPASS_CLASSES = {
        'KeepassXC': KeepassXC,
        'KeepassHTTP': KeepassHTTP,
    }

    # This class is instantiated per task, so we need a few class
    # attributes to cache data across executions.

    # We store this as a class attribute in order to keep the
    # connection to KeePass open (e.g. in case of ``KeepassXC``).
    keepass = None

    # again, instantiated per task, thus no ``lru_cache`` etc.
    become_pass_cache = {}

    @classmethod
    def get_keepass_class(cls):

        class_name = os.environ.get('KEEPASS_CLASS')
        if class_name is not None:
            return cls.KEEPASS_CLASSES[class_name]

        for process in psutil.process_iter():
            process_name = process.name() or ''
            if process_name.lower() in KEEPASSXC_PROCESS_NAMES:
                return cls.KEEPASS_CLASSES['KeepassXC']

        return cls.KEEPASS_CLASSES['KeepassHTTP']

    @classmethod
    def get_keepass(cls):
        if cls.keepass is None:
            cls.keepass = cls.get_keepass_class()()
        return cls.keepass

    @classmethod
    def get_password(cls, entity):
        try:
            keepass = cls.get_keepass()
            return keepass.get_password(entity.name)
        except AnsibleKeepassError as e:
            display.error(e)

        display.warning(
            'The password could not be obtained for ' +
            '{}. Either password not in database '.format(entity) +
            'or URL ssh://{} not set.'.format(entity)
        )

        return None

    def get_vars(self, loader, path, entities):
        super(VarsModule, self).get_vars(loader, path, entities)
        out_vars = {}
        cache = self.become_pass_cache
        for entity in entities:

            if entity not in cache:
                cache[entity] = self.get_password(entity)

            password = cache[entity]

            if password is not None:
                out_vars = combine_vars(
                    out_vars,
                    {'ansible_become_pass': password}
                )

        return out_vars
