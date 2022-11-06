import json
import yaml

from pathlib import Path
from urllib.parse import urlparse

from .misc import DotDict


relay_software_names = [
	'activityrelay',
	'aoderelay',
	'social.seattle.wa.us-relay',
	'unciarelay'
]


class RelayConfig(DotDict):
	apkeys = {
		'host',
		'whitelist_enabled',
		'blocked_software',
		'blocked_instances',
		'whitelist'
	}

	cachekeys = {
		'json',
		'objects',
		'digests'
	}


	def __init__(self, path, is_docker):
		if is_docker:
			path = '/data/relay.yaml'

		self._isdocker = is_docker
		self._path = Path(path).expanduser()

		super().__init__({
			'db': str(self._path.parent.joinpath(f'{self._path.stem}.jsonld')),
			'listen': '0.0.0.0',
			'port': 8080,
			'note': 'Make a note about your instance here.',
			'push_limit': 512,
			'host': 'relay.example.com',
			'blocked_software': [],
			'blocked_instances': [],
			'whitelist': [],
			'whitelist_enabled': False,
			'json': 1024,
			'objects': 1024,
			'digests': 1024
		})


	def __setitem__(self, key, value):
		if self._isdocker and key in ['db', 'listen', 'port']:
			return

		if key in ['blocked_instances', 'blocked_software', 'whitelist']:
			assert isinstance(value, (list, set, tuple))

		elif key in ['port', 'json', 'objects', 'digests']:
			assert isinstance(value, (int))

		elif key == 'whitelist_enabled':
			assert isinstance(value, bool)

		super().__setitem__(key, value)


	@property
	def db(self):
		return Path(self['db']).expanduser().resolve()


	@property
	def path(self):
		return self._path


	@property
	def actor(self):
		return f'https://{self.host}/actor'


	@property
	def inbox(self):
		return f'https://{self.host}/inbox'


	@property
	def keyid(self):
		return f'{self.actor}#main-key'


	def ban_instance(self, instance):
		if instance.startswith('http'):
			instance = urlparse(instance).hostname

		if self.is_banned(instance):
			return False

		self.blocked_instances.append(instance)
		return True


	def unban_instance(self, instance):
		if instance.startswith('http'):
			instance = urlparse(instance).hostname

		try:
			self.blocked_instances.remove(instance)
			return True

		except:
			return False


	def ban_software(self, software):
		if self.is_banned_software(software):
			return False

		self.blocked_software.append(software)
		return True


	def unban_software(self, software):
		try:
			self.blocked_software.remove(software)
			return True

		except:
			return False


	def add_whitelist(self, instance):
		if instance.startswith('http'):
			instance = urlparse(instance).hostname

		if self.is_whitelisted(instance):
			return False

		self.whitelist.append(instance)
		return True


	def del_whitelist(self, instance):
		if instance.startswith('http'):
			instance = urlparse(instance).hostname

		try:
			self.whitelist.remove(instance)
			return True

		except:
			return False


	def is_banned(self, instance):
		if instance.startswith('http'):
			instance = urlparse(instance).hostname

		return instance in self.blocked_instances


	def is_banned_software(self, software):
		if not software:
			return False

		return software.lower() in self.blocked_software


	def is_whitelisted(self, instance):
		if instance.startswith('http'):
			instance = urlparse(instance).hostname

		return instance in self.whitelist


	def load(self):
		options = {}

		try:
			options['Loader'] = yaml.FullLoader

		except AttributeError:
			pass

		try:
			with open(self.path) as fd:
				config = yaml.load(fd, **options)

		except FileNotFoundError:
			return False

		if not config:
			return False

		for key, value in config.items():
			if key in ['ap', 'cache']:
				for k, v in value.items():
					if k not in self:
						continue

					self[k] = v

			elif key not in self:
				continue

			self[key] = value

		if self.host.endswith('example.com'):
			return False

		return True


	def save(self):
		config = {
			'db': self['db'],
			'listen': self.listen,
			'port': self.port,
			'note': self.note,
			'push_limit': self.push_limit,
			'ap': {key: self[key] for key in self.apkeys},
			'cache': {key: self[key] for key in self.cachekeys}
		}

		with open(self._path, 'w') as fd:
			yaml.dump(config, fd, sort_keys=False)

		return config
