import aputils
import asyncio
import logging
import subprocess
import traceback

from pathlib import Path

from . import __version__, misc
from .misc import DotDict, Message, Response
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
body {{ background-color: #4b0082; }}
a {{ color: #26F; }}
a:visited {{ color: #46C; }}
a:hover {{ color: #8AF; }}
</style>
</head>
<body>
<p>This is an Activity Relay for fediverse instances.</p>
<p>{note}</p>
<p>You may subscribe to this relay with the address: <a href="https://{host}/actor">https://{host}/actor</a></p>
<p>To host your own relay, you may download the code at this address: <a href="https://github.com/atsu1125/relay">https://github.com/atsu1125/relay</a></p>
<br><p>List of {count} registered instances:<br>{targets}</p>
</body></html>"""

	return Response.new(text, ctype='html')


@register_route('GET', '/inbox')
@register_route('GET', '/actor')
async def actor(request):
	data = Message.new_actor(
		host = request.config.host, 
		pubkey = request.database.signer.pubkey
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

	request['actor'] = await request.app.client.get(request.signature.keyid, sign_headers=True)

	## reject if actor is empty
	if not request.actor:
		## ld signatures aren't handled atm, so just ignore it
		if request['message'].type == 'Delete':
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
	try:
		await request.actor.signer.validate_aiohttp_request(request)

	except aputils.SignatureValidationError as e:
		logging.verbose(f'signature validation failed for: {actor.id}')
		logging.debug(str(e))
		return Response.new_error(401, str(e), 'json')

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

	data = aputils.Webfinger.new(
		handle = 'relay',
		domain = request.config.host,
		actor = request.config.actor
	)

	return Response.new(data, ctype='json')


@register_route('GET', '/nodeinfo/{version:\d.\d\.json}')
async def nodeinfo(request):
	niversion = request.match_info['version'][:3]

	data = dict(
		name = 'activityrelay',
		version = version,
		protocols = ['activitypub'],
		open_regs = not request.config.whitelist_enabled,
		users = 1,
		metadata = {'peers': request.database.hostnames}
	)

	if niversion == '2.1':
		data['repo'] = 'https://git.pleroma.social/pleroma/relay'

	return Response.new(aputils.Nodeinfo.new(**data), ctype='json')


@register_route('GET', '/.well-known/nodeinfo')
async def nodeinfo_wellknown(request):
	data = aputils.WellKnownNodeinfo.new_template(request.config.host)
	return Response.new(data, ctype='json')
