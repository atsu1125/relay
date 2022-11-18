import asyncio
import json
import logging
import traceback

from Crypto.PublicKey import RSA
from urllib.parse import urlparse

from .misc import fetch_nodeinfo


class RelayDatabase(dict):
	def __init__(self, config):
		dict.__init__(self, {
			'relay-list': {},
			'private-key': None,
			'follow-requests': {},
			'version': 1
		})

		self.config = config
		self.PRIVKEY = None


	@property
	def PUBKEY(self):
		return self.PRIVKEY.publickey()


	@property
	def pubkey(self):
		return self.PUBKEY.exportKey('PEM').decode('utf-8')


	@property
	def privkey(self):
		return self['private-key']


	@property
	def hostnames(self):
		return tuple(self['relay-list'].keys())


	@property
	def inboxes(self):
		return tuple(data['inbox'] for data in self['relay-list'].values())


	def generate_key(self):
		self.PRIVKEY = RSA.generate(4096)
		self['private-key'] = self.PRIVKEY.exportKey('PEM').decode('utf-8')


	def load(self):
		new_db = True

		try:
			with self.config.db.open() as fd:
				data = json.load(fd)

			self['version'] = data.get('version', None)
			self['private-key'] = data.get('private-key')

			if self['version'] == None:
				self['version'] = 1

				if 'actorKeys' in data:
					self['private-key'] = data['actorKeys']['privateKey']

				for item in data.get('relay-list', []):
					domain = urlparse(item).hostname
					self['relay-list'][domain] = {
						'inbox': item,
						'followid': None
					}

			else:
				self['relay-list'] = data.get('relay-list', {})

			for domain, instance in self['relay-list'].items():
				if self.config.is_banned(domain) or (self.config.whitelist_enabled and not self.config.is_whitelisted(domain)):
					self.del_inbox(domain)
					continue

				if not instance.get('software'):
					nodeinfo = asyncio.run(fetch_nodeinfo(domain))

					if not nodeinfo:
						continue

					instance['software'] = nodeinfo.swname

			new_db = False

		except FileNotFoundError:
			pass

		except json.decoder.JSONDecodeError as e:
			if self.config.db.stat().st_size > 0:
				raise e from None

		if not self.privkey:
			logging.info("No actor keys present, generating 4096-bit RSA keypair.")
			self.generate_key()

		else:
			self.PRIVKEY = RSA.importKey(self.privkey)

		self.save()
		return not new_db


	def save(self):
		with self.config.db.open('w') as fd:
			json.dump(self, fd, indent=4)


	def get_inbox(self, domain, fail=False):
		if domain.startswith('http'):
			domain = urlparse(domain).hostname

		if domain not in self['relay-list']:
			if fail:
				raise KeyError(domain)

			return

		return self['relay-list'][domain]


	def add_inbox(self, inbox, followid=None, fail=False):
		assert inbox.startswith('https'), 'Inbox must be a url'
		domain = urlparse(inbox).hostname

		if self.get_inbox(domain):
			if fail:
				raise KeyError(domain)

			return False

		self['relay-list'][domain] = {
			'domain': domain,
			'inbox': inbox,
			'followid': followid
		}

		logging.verbose(f'Added inbox to database: {inbox}')
		return self['relay-list'][domain]


	def del_inbox(self, domain, followid=None, fail=False):
		data = self.get_inbox(domain, fail=False)

		if not data:
			if fail:
				raise KeyError(domain)

			return False

		if not data['followid'] or not followid or data['followid'] == followid:
			del self['relay-list'][data['domain']]
			logging.verbose(f'Removed inbox from database: {data["inbox"]}')
			return True

		if fail:
			raise ValueError('Follow IDs do not match')

		logging.debug(f'Follow ID does not match: db = {data["followid"]}, object = {followid}')
		return False


	def set_followid(self, domain, followid):
		data = self.get_inbox(domain, fail=True)
		data['followid'] = followid


	def get_request(self, domain, fail=True):
		if domain.startswith('http'):
			domain = urlparse(domain).hostname

		try:
			return self['follow-requests'][domain]

		except KeyError as e:
			if fail:
				raise e


	def add_request(self, actor, inbox, followid):
		domain = urlparse(inbox).hostname

		try:
			request = self.get_request(domain)
			request['followid'] = followid

		except KeyError:
			pass

		self['follow-requests'][domain] = {
			'actor': actor,
			'inbox': inbox,
			'followid': followid
		}


	def del_request(self, domain):
		if domain.startswith('http'):
			domain = urlparse(inbox).hostname

		del self['follow-requests'][domain]
