import asyncio
import logging
import os
import queue
import signal
import threading
import traceback

from aiohttp import web
from datetime import datetime, timedelta

from .config import RelayConfig
from .database import RelayDatabase
from .http_client import HttpClient
from .misc import DotDict, check_open_port, set_app
from .views import routes


class Application(web.Application):
	def __init__(self, cfgpath):
		web.Application.__init__(self)

		self['starttime'] = None
		self['running'] = False
		self['config'] = RelayConfig(cfgpath)

		if not self['config'].load():
			self['config'].save()

		if self.config.is_docker:
			self.config.update({
				'db': '/data/relay.jsonld',
				'listen': '0.0.0.0',
				'port': 8080
			})

		self['workers'] = []
		self['last_worker'] = 0

		set_app(self)

		self['database'] = RelayDatabase(self['config'])
		self['database'].load()

		self['client'] = HttpClient(
			database = self.database,
			limit = self.config.push_limit,
			timeout = self.config.timeout,
			cache_size = self.config.json_cache
		)

		self.set_signal_handler()


	@property
	def client(self):
		return self['client']


	@property
	def config(self):
		return self['config']


	@property
	def database(self):
		return self['database']


	@property
	def uptime(self):
		if not self['starttime']:
			return timedelta(seconds=0)

		uptime = datetime.now() - self['starttime']

		return timedelta(seconds=uptime.seconds)


	def push_message(self, inbox, message):
		if self.config.workers <= 0:
			return asyncio.ensure_future(self.client.post(inbox, message))

		worker = self['workers'][self['last_worker']]
		worker.queue.put((inbox, message))

		self['last_worker'] += 1

		if self['last_worker'] >= len(self['workers']):
			self['last_worker'] = 0


	def set_signal_handler(self):
		for sig in {'SIGHUP', 'SIGINT', 'SIGQUIT', 'SIGTERM'}:
			try:
				signal.signal(getattr(signal, sig), self.stop)

			# some signals don't exist in windows, so skip them
			except AttributeError:
				pass


	def run(self):
		if not check_open_port(self.config.listen, self.config.port):
			return logging.error(f'A server is already running on port {self.config.port}')

		for route in routes:
			self.router.add_route(*route)

		logging.info(f'Starting webserver at {self.config.host} ({self.config.listen}:{self.config.port})')
		asyncio.run(self.handle_run())


	def stop(self, *_):
		self['running'] = False


	async def handle_run(self):
		self['running'] = True

		if self.config.workers > 0:
			for i in range(self.config.workers):
				worker = PushWorker(self)
				worker.start()

				self['workers'].append(worker)

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
		self['workers'].clear()


class PushWorker(threading.Thread):
	def __init__(self, app):
		threading.Thread.__init__(self)
		self.app = app
		self.queue = queue.Queue()


	def run(self):
		self.client = HttpClient(
			database = self.app.database,
			limit = self.app.config.push_limit,
			timeout = self.app.config.timeout,
			cache_size = self.app.config.json_cache
		)

		asyncio.run(self.handle_queue())


	async def handle_queue(self):
		while self.app['running']:
			try:
				inbox, message = self.queue.get(block=True, timeout=0.25)
				self.queue.task_done()
				logging.verbose(f'New push from Thread-{threading.get_ident()}')
				await self.client.post(inbox, message)

			except queue.Empty:
				pass

			## make sure an exception doesn't bring down the worker
			except Exception:
				traceback.print_exc()

		await self.client.close()


## Can't sub-class web.Request, so let's just add some properties
def request_actor(self):
	try: return self['actor']
	except KeyError: pass


def request_instance(self):
	try: return self['instance']
	except KeyError: pass


def request_message(self):
	try: return self['message']
	except KeyError: pass


def request_signature(self):
	if 'signature' not in self._state:
		try: self['signature'] = DotDict.new_from_signature(self.headers['signature'])
		except KeyError: return

	return self['signature']


setattr(web.Request, 'actor', property(request_actor))
setattr(web.Request, 'instance', property(request_instance))
setattr(web.Request, 'message', property(request_message))
setattr(web.Request, 'signature', property(request_signature))

setattr(web.Request, 'config', property(lambda self: self.app.config))
setattr(web.Request, 'database', property(lambda self: self.app.database))
