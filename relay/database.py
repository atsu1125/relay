import aputils
import asyncio
import json
import logging
import traceback

from urllib.parse import urlparse


class RelayDatabase(dict):
	def __init__(self, config):
		dict.__init__(self, {
			'relay-list': {},
			'private-key': None,
			'follow-requests': {},
			'version': 1
		})

		self.config = config
		self.signer = None


	@property
	def hostnames(self):
		return tuple(self['relay-list'].keys())


	@property
	def inboxes(self):
		return tuple(data['inbox'] for data in self['relay-list'].values())


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
						'domain': domain,
						'inbox': item,
						'followid': None
					}

			else:
				self['relay-list'] = data.get('relay-list', {})

			for domain, instance in self['relay-list'].items():
				if self.config.is_banned(domain) or (self.config.whitelist_enabled and not self.config.is_whitelisted(domain)):
					self.del_inbox(domain)
					continue

				if not instance.get('domain'):
					instance['domain'] = domain

			new_db = False

		except FileNotFoundError:
			pass

		except json.decoder.JSONDecodeError as e:
			if self.config.db.stat().st_size > 0:
				raise e from None

		if not self['private-key']:
			logging.info("No actor keys present, generating 4096-bit RSA keypair.")
			self.signer = aputils.Signer.new(self.config.keyid, size=4096)
			self['private-key'] = self.signer.export()

		else:
			self.signer = aputils.Signer(self['private-key'], self.config.keyid)

		self.save()
		return not new_db


	def save(self):
		with self.config.db.open('w') as fd:
			json.dump(self, fd, indent=4)


	def get_inbox(self, domain, fail=False):
		if domain.startswith('http'):
			domain = urlparse(domain).hostname

		inbox = self['relay-list'].get(domain)

		if inbox:
			return inbox

		if fail:
			raise KeyError(domain)


	def add_inbox(self, inbox, followid=None, software=None):
		assert inbox.startswith('https'), 'Inbox must be a url'
		domain = urlparse(inbox).hostname
		instance = self.get_inbox(domain)

		if instance:
			if followid:
				instance['followid'] = followid

			if software:
				instance['software'] = software

			return instance

		self['relay-list'][domain] = {
			'domain': domain,
			'inbox': inbox,
			'followid': followid,
			'software': software
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


	def distill_inboxes(self, message):
		src_domains = {
			message.domain,
			urlparse(message.objectid).netloc
		}

		for domain, instance in self['relay-list'].items():
			if domain not in src_domains:
				yield instance['inbox']
