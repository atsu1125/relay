import asyncio
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
	targets = '<br>'.join(request.database.hostnames)
	note = request.config.note
	count = len(request.database.hostnames)
	host = request.config.host

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
		host = request.config.host, 
		pubkey = request.database.pubkey
	)

	return Response.new(data, ctype='activity')


@register_route('POST', '/inbox')
@register_route('POST', '/actor')
async def inbox(request):
	config = request.config
	database = request.database

	## reject if missing signature header
	if not request.signature:
		logging.verbose('Actor missing signature header')
		raise HTTPUnauthorized(body='missing signature')

	try:
		request['message'] = await request.json(loads=Message.new_from_json)

		## reject if there is no message
		if not request.message:
			logging.verbose('empty message')
			return Response.new_error(400, 'missing message', 'json')

		## reject if there is no actor in the message
		if 'actor' not in request.message:
			logging.verbose('actor not in message')
			return Response.new_error(400, 'no actor in message', 'json')

	except:
		## this code should hopefully never get called
		traceback.print_exc()
		logging.verbose('Failed to parse inbox message')
		return Response.new_error(400, 'failed to parse message', 'json')

	request['actor'] = await misc.request(request.signature.keyid)

	## reject if actor is empty
	if not request.actor:
		## ld signatures aren't handled atm, so just ignore it
		if data.type == 'Delete':
			logging.verbose(f'Instance sent a delete which cannot be handled')
			return Response.new(status=202)

		logging.verbose(f'Failed to fetch actor: {request.signature.keyid}')
		return Response.new_error(400, 'failed to fetch actor', 'json')

	request['instance'] = request.database.get_inbox(request['actor'].inbox)

	## reject if the actor isn't whitelisted while the whiltelist is enabled
	if config.whitelist_enabled and not config.is_whitelisted(request.actor.domain):
		logging.verbose(f'Rejected actor for not being in the whitelist: {request.actor.id}')
		return Response.new_error(403, 'access denied', 'json')

	## reject if actor is banned
	if request.config.is_banned(request.actor.domain):
		logging.verbose(f'Ignored request from banned actor: {actor.id}')
		return Response.new_error(403, 'access denied', 'json')

	## reject if the signature is invalid
	if not (await misc.validate_signature(request.actor, request.signature, request)):
		logging.verbose(f'signature validation failed for: {actor.id}')
		return Response.new_error(401, 'signature check failed', 'json')

	## reject if activity type isn't 'Follow' and the actor isn't following
	if request.message.type != 'Follow' and not database.get_inbox(request.actor.domain):
		logging.verbose(f'Rejected actor for trying to post while not following: {request.actor.id}')
		return Response.new_error(401, 'access denied', 'json')

	logging.debug(f">> payload {request.message.to_json(4)}")

	asyncio.ensure_future(run_processor(request))
	return Response.new(status=202)


@register_route('GET', '/.well-known/webfinger')
async def webfinger(request):
	try:
		subject = request.query['resource']

	except KeyError:
		return Response.new_error(400, 'missing \'resource\' query key', 'json')

	if subject != f'acct:relay@{request.config.host}':
		return Response.new_error(404, 'user not found', 'json')

	data = {
		'subject': subject,
		'aliases': [request.config.actor],
		'links': [
			{'href': request.config.actor, 'rel': 'self', 'type': 'application/activity+json'},
			{'href': request.config.actor, 'rel': 'self', 'type': 'application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"'}
		]
	}

	return Response.new(data, ctype='json')


@register_route('GET', '/nodeinfo/{version:\d.\d\.json}')
async def nodeinfo_2_0(request):
	niversion = request.match_info['version'][:3]
	data = {
		'openRegistrations': not request.config.whitelist_enabled,
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
			'peers': request.database.hostnames
		},
		'version': niversion
	}

	if version == '2.1':
		data['software']['repository'] = 'https://git.pleroma.social/pleroma/relay'

	return Response.new(data, ctype='json')


@register_route('GET', '/.well-known/nodeinfo')
async def nodeinfo_wellknown(request):
	data = WKNodeinfo.new(
		v20 = f'https://{request.config.host}/nodeinfo/2.0.json',
		v21 = f'https://{request.config.host}/nodeinfo/2.1.json'
	)

	return Response.new(data, ctype='json')


@register_route('GET', '/stats')
async def stats(request):
    return Response.new(STATS, ctype='json')
