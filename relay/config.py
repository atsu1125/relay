import json
import os
import yaml

from functools import cached_property
from pathlib import Path
from urllib.parse import urlparse

from .misc import DotDict, boolean


RELAY_SOFTWARE = [
	'activityrelay', # https://git.pleroma.social/pleroma/relay
	'aoderelay', # https://git.asonix.dog/asonix/relay
	'feditools-relay' # https://git.ptzo.gdn/feditools/relay
]

APKEYS = [
	'host',
	'whitelist_enabled',
	'blocked_software',
	'blocked_instances',
	'whitelist'
]


class RelayConfig(DotDict):
	def __init__(self, path):
		DotDict.__init__(self, {})

		if self.is_docker:
			path = '/data/config.yaml'

		self._path = Path(path).expanduser()
		self.reset()


	def __setitem__(self, key, value):
		if key in ['blocked_instances', 'blocked_software', 'whitelist']:
			assert isinstance(value, (list, set, tuple))

		elif key in ['port', 'workers', 'json_cache', 'timeout']:
			if not isinstance(value, int):
				value = int(value)

		elif key == 'whitelist_enabled':
			if not isinstance(value, bool):
				value = boolean(value)

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


	@cached_property
	def is_docker(self):
		return bool(os.environ.get('DOCKER_RUNNING'))


	def reset(self):
		self.clear()
		self.update({
			'db': str(self._path.parent.joinpath(f'{self._path.stem}.jsonld')),
			'listen': '0.0.0.0',
			'port': 8080,
			'note': 'Make a note about your instance here.',
			'push_limit': 512,
			'json_cache': 1024,
			'timeout': 10,
			'workers': 0,
			'host': 'relay.example.com',
			'whitelist_enabled': False,
			'blocked_software': [],
			'blocked_instances': [],
			'whitelist': []
		})


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
		self.reset()

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
			if key in ['ap']:
				for k, v in value.items():
					if k not in self:
						continue

					self[k] = v

				continue

			elif key not in self:
				continue

			self[key] = value

		if self.host.endswith('example.com'):
			return False

		return True


	def save(self):
		config = {
			# just turning config.db into a string is good enough for now
			'db': str(self.db),
			'listen': self.listen,
			'port': self.port,
			'note': self.note,
			'push_limit': self.push_limit,
			'workers': self.workers,
			'json_cache': self.json_cache,
			'timeout': self.timeout,
			'ap': {key: self[key] for key in APKEYS}
		}

		with open(self._path, 'w') as fd:
			yaml.dump(config, fd, sort_keys=False)

		return config
