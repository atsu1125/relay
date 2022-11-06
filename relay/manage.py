import Crypto
import asyncio
import click
import json
import logging
import os
import platform

from aiohttp.web import AppRunner, TCPSite
from cachetools import LRUCache

from . import app, misc, views, __version__
from .config import DotDict, RelayConfig, relay_software_names
from .database import RelayDatabase


@click.group('cli', context_settings={'show_default': True}, invoke_without_command=True)
@click.option('--config', '-c', default='relay.yaml', help='path to the relay\'s config')
@click.version_option(version=__version__, prog_name='ActivityRelay')
@click.pass_context
def cli(ctx, config):
	app['is_docker'] = bool(os.environ.get('DOCKER_RUNNING'))
	app['config'] = RelayConfig(config, app['is_docker'])

	if not app['config'].load():
		app['config'].save()

	app['database'] = RelayDatabase(app['config'])
	app['database'].load()

	app['cache'] = DotDict()
	app['semaphore'] = asyncio.Semaphore(app['config']['push_limit'])

	for key in app['config'].cachekeys:
		app['cache'][key] = LRUCache(app['config'][key])

	if not ctx.invoked_subcommand:
		if app['config'].host.endswith('example.com'):
			relay_setup.callback()

		else:
			relay_run.callback()


@cli.group('inbox')
@click.pass_context
def cli_inbox(ctx):
	'Manage the inboxes in the database'
	pass


@cli_inbox.command('list')
def cli_inbox_list():
	'List the connected instances or relays'

	click.echo('Connected to the following instances or relays:')

	for inbox in app['database'].inboxes:
		click.echo(f'- {inbox}')


@cli_inbox.command('follow')
@click.argument('actor')
def cli_inbox_follow(actor):
	'Follow an actor (Relay must be running)'

	config = app['config']
	database = app['database']

	if config.is_banned(actor):
		return click.echo(f'Error: Refusing to follow banned actor: {actor}')

	if not actor.startswith('http'):
		actor = f'https://{actor}/actor'

	if database.get_inbox(actor):
		return click.echo(f'Error: Already following actor: {actor}')

	actor_data = run_in_loop(misc.request, actor, sign_headers=True)

	if not actor_data:
		return click.echo(f'Error: Failed to fetch actor: {actor}')

	inbox = misc.get_actor_inbox(actor_data)

	database.add_inbox(inbox)
	database.save()

	run_in_loop(misc.follow_remote_actor, actor)
	click.echo(f'Sent follow message to actor: {actor}')


@cli_inbox.command('unfollow')
@click.argument('actor')
def cli_inbox_unfollow(actor):
	'Unfollow an actor (Relay must be running)'

	database = app['database']

	if not actor.startswith('http'):
		actor = f'https://{actor}/actor'

	if database.del_inbox(actor):
		database.save()
		run_in_loop(misc.unfollow_remote_actor, actor)
		return click.echo(f'Sent unfollow message to: {actor}')

	return click.echo(f'Error: Not following actor: {actor}')


@cli_inbox.command('add')
@click.argument('inbox')
def cli_inbox_add(inbox):
	'Add an inbox to the database'

	database = app['database']
	config = app['config']

	if not inbox.startswith('http'):
		inbox = f'https://{inbox}/inbox'

	if config.is_banned(inbox):
		return click.echo(f'Error: Refusing to add banned inbox: {inbox}')

	if database.add_inbox(inbox):
		database.save()
		return click.echo(f'Added inbox to the database: {inbox}')

	click.echo(f'Error: Inbox already in database: {inbox}')


@cli_inbox.command('remove')
@click.argument('inbox')
def cli_inbox_remove(inbox):
	'Remove an inbox from the database'

	database = app['database']

	try:
		dbinbox = database.get_inbox(inbox, fail=True)

	except KeyError:
		click.echo(f'Error: Inbox does not exist: {inbox}')
		return

	database.del_inbox(dbinbox['domain'])
	database.save()

	click.echo(f'Removed inbox from the database: {inbox}')


@cli.group('instance')
def cli_instance():
	'Manage instance bans'
	pass


@cli_instance.command('list')
def cli_instance_list():
	'List all banned instances'

	click.echo('Banned instances or relays:')

	for domain in app['config'].blocked_instances:
		click.echo(f'- {domain}')


@cli_instance.command('ban')
@click.argument('target')
def cli_instance_ban(target):
	'Ban an instance and remove the associated inbox if it exists'

	config = app['config']
	database = app['database']

	if target.startswith('http'):
		target = urlparse(target).hostname

	if config.ban_instance(target):
		config.save()

		if database.del_inbox(target):
			database.save()

		click.echo(f'Banned instance: {target}')
		return

	click.echo(f'Instance already banned: {target}')


@cli_instance.command('unban')
@click.argument('target')
def cli_instance_unban(target):
	'Unban an instance'

	config = app['config']

	if config.unban_instance(target):
		config.save()

		click.echo(f'Unbanned instance: {target}')
		return

	click.echo(f'Instance wasn\'t banned: {target}')


@cli.group('software')
def cli_software():
	'Manage banned software'
	pass


@cli_software.command('list')
def cli_software_list():
	'List all banned software'

	click.echo('Banned software:')

	for software in app['config'].blocked_software:
		click.echo(f'- {software}')


@cli_software.command('ban')
@click.option('--fetch-nodeinfo/--ignore-nodeinfo', '-f', 'fetch_nodeinfo', default=False,
	help='Treat NAME like a domain and try to fet the software name from nodeinfo'
)
@click.argument('name')
def cli_software_ban(name, fetch_nodeinfo):
	'Ban software. Use RELAYS for NAME to ban relays'

	config = app['config']

	if name == 'RELAYS':
		for name in relay_software_names:
			config.ban_software(name)

		config.save()
		return click.echo('Banned all relay software')

	if fetch_nodeinfo:
		software = run_in_loop(fetch_nodeinfo, name)

		if not software:
			click.echo(f'Failed to fetch software name from domain: {name}')

		name = software

	if config.ban_software(name):
		config.save()
		return click.echo(f'Banned software: {name}')

	click.echo(f'Software already banned: {name}')


@cli_software.command('unban')
@click.option('--fetch-nodeinfo/--ignore-nodeinfo', '-f', 'fetch_nodeinfo', default=False,
	help='Treat NAME like a domain and try to fet the software name from nodeinfo'
)
@click.argument('name')
def cli_software_unban(name, fetch_nodeinfo):
	'Ban software. Use RELAYS for NAME to unban relays'

	config = app['config']

	if name == 'RELAYS':
		for name in relay_software_names:
			config.unban_software(name)

		config.save()
		return click.echo('Unbanned all relay software')

	if fetch_nodeinfo:
		software = run_in_loop(fetch_nodeinfo, name)

		if not software:
			click.echo(f'Failed to fetch software name from domain: {name}')

		name = software

	if config.unban_software(name):
		config.save()
		return click.echo(f'Unbanned software: {name}')

	click.echo(f'Software wasn\'t banned: {name}')



@cli.group('whitelist')
def cli_whitelist():
	'Manage the instance whitelist'
	pass


@cli_whitelist.command('list')
def cli_whitelist_list():
	click.echo('Current whitelisted domains')

	for domain in app['config'].whitelist:
		click.echo(f'- {domain}')


@cli_whitelist.command('add')
@click.argument('instance')
def cli_whitelist_add(instance):
	'Add an instance to the whitelist'

	config = app['config']

	if not config.add_whitelist(instance):
		return click.echo(f'Instance already in the whitelist: {instance}')

	config.save()
	click.echo(f'Instance added to the whitelist: {instance}')


@cli_whitelist.command('remove')
@click.argument('instance')
def cli_whitelist_remove(instance):
	'Remove an instance from the whitelist'

	config = app['config']
	database = app['database']

	if not config.del_whitelist(instance):
		return click.echo(f'Instance not in the whitelist: {instance}')

	config.save()

	if config.whitelist_enabled:
		if database.del_inbox(inbox):
			database.save()

	click.echo(f'Removed instance from the whitelist: {instance}')


@cli.command('setup')
def relay_setup():
	'Generate a new config'

	config = app['config']

	while True:
		config.host = click.prompt('What domain will the relay be hosted on?', default=config.host)

		if not config.host.endswith('example.com'):
			break

		click.echo('The domain must not be example.com')

	config.listen = click.prompt('Which address should the relay listen on?', default=config.listen)

	while True:
		config.port = click.prompt('What TCP port should the relay listen on?', default=config.port, type=int)
		break

	config.save()

	if not app['is_docker'] and click.confirm('Relay all setup! Would you like to run it now?'):
		relay_run.callback()


@cli.command('run')
def relay_run():
	'Run the relay'

	config = app['config']

	if config.host.endswith('example.com'):
		return click.echo('Relay is not set up. Please edit your relay config or run "activityrelay setup".')

	vers_split = platform.python_version().split('.')
	pip_command = 'pip3 uninstall pycrypto && pip3 install pycryptodome'

	if Crypto.__version__ == '2.6.1':
		if int(vers_split[1]) > 7:
			click.echo('Error: PyCrypto is broken on Python 3.8+. Please replace it with pycryptodome before running again. Exiting...')
			return click.echo(pip_command)

		else:
			click.echo('Warning: PyCrypto is old and should be replaced with pycryptodome')
			return click.echo(pip_command)

	if not misc.check_open_port(config.listen, config.port):
		return click.echo(f'Error: A server is already running on port {config.port}')

	# web pages
	app.router.add_get('/', views.home)

	# endpoints
	app.router.add_post('/actor', views.inbox)
	app.router.add_post('/inbox', views.inbox)
	app.router.add_get('/actor', views.actor)
	app.router.add_get('/nodeinfo/2.0.json', views.nodeinfo_2_0)
	app.router.add_get('/.well-known/nodeinfo', views.nodeinfo_wellknown)
	app.router.add_get('/.well-known/webfinger', views.webfinger)

	if logging.DEBUG >= logging.root.level:
		app.router.add_get('/stats', views.stats)

	loop = asyncio.new_event_loop()
	asyncio.set_event_loop(loop)
	asyncio.ensure_future(handle_start_webserver(), loop=loop)
	loop.run_forever()


def run_in_loop(func, *args, **kwargs):
	loop = asyncio.new_event_loop()
	return loop.run_until_complete(func(*args, **kwargs))


async def handle_start_webserver():
	config = app['config']
	runner = AppRunner(app, access_log_format='%{X-Forwarded-For}i "%r" %s %b "%{Referer}i" "%{User-Agent}i"')

	logging.info(f'Starting webserver at {config.host} ({config.listen}:{config.port})')
	await runner.setup()

	site = TCPSite(runner, config.listen, config.port)
	await site.start()


def main():
	cli(prog_name='relay')


if __name__ == '__main__':
	click.echo('Running relay.manage is depreciated. Run `activityrelay [command]` instead.')
