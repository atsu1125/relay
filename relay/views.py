import logging
import subprocess
import traceback

from pathlib import Path

from . import __version__, misc
from .http_debug import STATS
from .misc import DotDict, Message, Response, WKNodeinfo
from .processors import run_processor


routes = []
version = __version__


if Path(__file__).parent.parent.joinpath('.git').exists():
	try:
		commit_label = subprocess.check_output(["git", "rev-parse", "HEAD"]).strip().decode('ascii')
		version = f'{__version__} {commit_label}'

	except:
		pass


def register_route(method, path):
	def wrapper(func):
		routes.append([method, path, func])
		return func

	return wrapper


@register_route('GET', '/')
async def home(request):
	targets = '<br>'.join(request.app.database.hostnames)
	note = request.app.config.note
	count = len(request.app.database.hostnames)
	host = request.app.config.host

	text = f"""
<html><head>
<title>ActivityPub Relay at {host}</title>
<style>
p {{ color: #FFFFFF; font-family: monospace, arial; font-size: 100%; }}
body {{ background-color: #000000; }}
a {{ color: #26F; }}
a:visited {{ color: #46C; }}
a:hover {{ color: #8AF; }}
</style>
</head>
<body>
<p>This is an Activity Relay for fediverse instances.</p>
<p>{note}</p>
<p>You may subscribe to this relay with the address: <a href="https://{host}/actor">https://{host}/actor</a></p>
<p>To host your own relay, you may download the code at this address: <a href="https://git.pleroma.social/pleroma/relay">https://git.pleroma.social/pleroma/relay</a></p>
<br><p>List of {count} registered instances:<br>{targets}</p>
</body></html>"""

	return Response.new(text, ctype='html')


@register_route('GET', '/inbox')
@register_route('GET', '/actor')
async def actor(request):
	data = Message.new_actor(
		host = request.app.config.host, 
		pubkey = request.app.database.pubkey
	)

	return Response.new(data, ctype='activity')


@register_route('POST', '/inbox')
@register_route('POST', '/actor')
async def inbox(request):
	config = request.app.config
	database = request.app.database

	## reject if missing signature header
	try:
		signature = DotDict.new_from_signature(request.headers['signature'])

	except KeyError:
		logging.verbose('Actor missing signature header')
		raise HTTPUnauthorized(body='missing signature')

	## read message
	try:
		data = await request.json(loads=Message.new_from_json)

		## reject if there is no actor in the message
		if 'actor' not in data:
			logging.verbose('actor not in data')
			return Response.new_error(400, 'no actor in message', 'json')

	except:
		traceback.print_exc()
		logging.verbose('Failed to parse inbox message')
		return Response.new_error(400, 'failed to parse message', 'json')

	actor = await misc.request(signature.keyid)
	software = await misc.fetch_nodeinfo(actor.domain)

	## reject if actor is empty
	if not actor:
		logging.verbose(f'Failed to fetch actor: {actor.id}')
		return Response.new_error(400, 'failed to fetch actor', 'json')

	## reject if the actor isn't whitelisted while the whiltelist is enabled
	elif config.whitelist_enabled and not config.is_whitelisted(actor.domain):
		logging.verbose(f'Rejected actor for not being in the whitelist: {actor.id}')
		return Response.new_error(403, 'access denied', 'json')

	## reject if actor is banned
	if request.app['config'].is_banned(actor.domain):
		logging.verbose(f'Ignored request from banned actor: {actor.id}')
		return Response.new_error(403, 'access denied', 'json')

	## reject if software used by actor is banned
	if config.is_banned_software(software):
		logging.verbose(f'Rejected actor for using specific software: {software}')
		return Response.new_error(403, 'access denied', 'json')

	## reject if the signature is invalid
	if not (await misc.validate_signature(actor, signature, request)):
		logging.verbose(f'signature validation failed for: {actor.id}')
		return Response.new_error(401, 'signature check failed', 'json')

	## reject if activity type isn't 'Follow' and the actor isn't following
	if data['type'] != 'Follow' and not database.get_inbox(actor.domain):
		logging.verbose(f'Rejected actor for trying to post while not following: {actor.id}')
		return Response.new_error(401, 'access denied', 'json')

	logging.debug(f">> payload {data}")

	await run_processor(request, actor, data, software)
	return Response.new(status=202)


@register_route('GET', '/.well-known/webfinger')
async def webfinger(request):
	subject = request.query['resource']

	if subject != f'acct:relay@{request.app.config.host}':
		return Response.new_error(404, 'user not found', 'json')

	data = {
		'subject': subject,
		'aliases': [request.app.config.actor],
		'links': [
			{'href': request.app.config.actor, 'rel': 'self', 'type': 'application/activity+json'},
			{'href': request.app.config.actor, 'rel': 'self', 'type': 'application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"'}
		]
	}

	return Response.new(data, ctype='json')


@register_route('GET', '/nodeinfo/{version:\d.\d\.json}')
async def nodeinfo_2_0(request):
	niversion = request.match_info['version'][:3]
	data = {
		'openRegistrations': not request.app.config.whitelist_enabled,
		'protocols': ['activitypub'],
		'services': {
			'inbound': [],
			'outbound': []
		},
		'software': {
			'name': 'activityrelay',
			'version': version
		},
		'usage': {
			'localPosts': 0,
			'users': {
				'total': 1
			}
		},
		'metadata': {
			'peers': request.app.database.hostnames
		},
		'version': niversion
	}

	if version == '2.1':
		data['software']['repository'] = 'https://git.pleroma.social/pleroma/relay'

	return Response.new(data, ctype='json')


@register_route('GET', '/.well-known/nodeinfo')
async def nodeinfo_wellknown(request):
	data = WKNodeinfo.new(
		v20 = f'https://{request.app.config.host}/nodeinfo/2.0.json',
		v21 = f'https://{request.app.config.host}/nodeinfo/2.1.json'
	)

	return Response.new(data, ctype='json')


@register_route('GET', '/stats')
async def stats(request):
    return Response.new(STATS, ctype='json')
