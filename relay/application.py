import asyncio
import logging
import os
import signal

from aiohttp import web
from cachetools import LRUCache
from datetime import datetime, timedelta

from .config import RelayConfig
from .database import RelayDatabase
from .misc import DotDict, check_open_port, set_app
from .views import routes


class Application(web.Application):
	def __init__(self, cfgpath):
		web.Application.__init__(self)

		self['starttime'] = None
		self['running'] = False
		self['is_docker'] = bool(os.environ.get('DOCKER_RUNNING'))
		self['config'] = RelayConfig(cfgpath, self['is_docker'])

		if not self['config'].load():
			self['config'].save()

		self['database'] = RelayDatabase(self['config'])
		self['database'].load()

		self['cache'] = DotDict({key: Cache(maxsize=self['config'][key]) for key in self['config'].cachekeys})
		self['semaphore'] = asyncio.Semaphore(self['config'].push_limit)

		self.set_signal_handler()
		set_app(self)


	@property
	def cache(self):
		return self['cache']


	@property
	def config(self):
		return self['config']


	@property
	def database(self):
		return self['database']


	@property
	def is_docker(self):
		return self['is_docker']


	@property
	def semaphore(self):
		return self['semaphore']


	@property
	def uptime(self):
		if not self['starttime']:
			return timedelta(seconds=0)

		uptime = datetime.now() - self['starttime']

		return timedelta(seconds=uptime.seconds)


	def set_signal_handler(self):
		signal.signal(signal.SIGHUP, self.stop)
		signal.signal(signal.SIGINT, self.stop)
		signal.signal(signal.SIGQUIT, self.stop)
		signal.signal(signal.SIGTERM, self.stop)


	def run(self):
		if not check_open_port(self.config.listen, self.config.port):
			return logging.error(f'A server is already running on port {self.config.port}')

		for route in routes:
			if route[1] == '/stats' and logging.DEBUG < logging.root.level:
				continue

			self.router.add_route(*route)

		logging.info(f'Starting webserver at {self.config.host} ({self.config.listen}:{self.config.port})')
		asyncio.run(self.handle_run())


	def stop(self, *_):
		self['running'] = False


	async def handle_run(self):
		self['running'] = True

		runner = web.AppRunner(self, access_log_format='%{X-Forwarded-For}i "%r" %s %b "%{User-Agent}i"')
		await runner.setup()

		site = web.TCPSite(runner,
			host = self.config.listen,
			port = self.config.port,
			reuse_address = True
		)

		await site.start()
		self['starttime'] = datetime.now()

		while self['running']:
			await asyncio.sleep(0.25)

		await site.stop()

		self['starttime'] = None
		self['running'] = False


class Cache(LRUCache):
	def set_maxsize(self, value):
		self.__maxsize = int(value)
