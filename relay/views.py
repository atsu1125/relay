import logging
import subprocess
import traceback

from aiohttp.web import HTTPForbidden, HTTPUnauthorized, Response, json_response

from . import __version__, app, misc
from .http_debug import STATS
from .misc import Message
from .processors import run_processor


try:
	commit_label = subprocess.check_output(["git", "rev-parse", "HEAD"]).strip().decode('ascii')
	version = f'{__version__} {commit_label}'

except:
	version = __version__


async def home(request):
	targets = '<br>'.join(app['database'].hostnames)
	text = """
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
</body></html>""".format(host=request.host, note=app['config'].note, targets=targets, count=len(app['database'].hostnames))

	return Response(
		status = 200,
		content_type = 'text/html',
		charset = 'utf-8',
		text = text
	)


async def actor(request):
	config = app['config']
	database = app['database']

	data = Message.new_actor(
		host = config.host, 
		pubkey = database.pubkey
	)

	return json_response(data, content_type='application/activity+json')


async def inbox(request):
	config = app['config']
	database = app['database']

	## reject if missing signature header
	if 'signature' not in request.headers:
		logging.verbose('Actor missing signature header')
		raise HTTPUnauthorized(body='missing signature')

	## read message and get actor id and domain
	try:
		data = await request.json(loads=Message.new_from_json)

		if 'actor' not in data:
			raise KeyError('actor')

	## reject if there is no actor in the message
	except KeyError:
		logging.verbose('actor not in data')
		raise HTTPUnauthorized(body='no actor in message')

	except:
		traceback.print_exc()
		logging.verbose('Failed to parse inbox message')
		raise HTTPUnauthorized(body='failed to parse message')

	actor = await misc.request(data.actorid)

	## reject if actor is empty
	if not actor:
		logging.verbose(f'Failed to fetch actor: {data.actorid}')
		raise HTTPUnauthorized('failed to fetch actor')

	## reject if the actor isn't whitelisted while the whiltelist is enabled
	elif config.whitelist_enabled and not config.is_whitelisted(data.domain):
		logging.verbose(f'Rejected actor for not being in the whitelist: {data.actorid}')
		raise HTTPForbidden(body='access denied')

	## reject if actor is banned
	if app['config'].is_banned(data.domain):
		logging.verbose(f'Ignored request from banned actor: {data.actorid}')
		raise HTTPForbidden(body='access denied')

	## reject if software used by actor is banned
	if len(config.blocked_software):
		software = await misc.fetch_nodeinfo(data.domain)

		if config.is_banned_software(software):
			logging.verbose(f'Rejected actor for using specific software: {software}')
			raise HTTPForbidden(body='access denied')

	## reject if the signature is invalid
	if not (await misc.validate_signature(data.actorid, request)):
		logging.verbose(f'signature validation failed for: {data.actorid}')
		raise HTTPUnauthorized(body='signature check failed, signature did not match key')

	## reject if activity type isn't 'Follow' and the actor isn't following
	if data['type'] != 'Follow' and not database.get_inbox(data.domain):
		logging.verbose(f'Rejected actor for trying to post while not following: {data.actorid}')
		raise HTTPUnauthorized(body='access denied')

	logging.debug(f">> payload {data}")

	await run_processor(request, actor, data, software)
	return Response(body=b'{}', content_type='application/activity+json')


async def webfinger(request):
	config = app['config']
	subject = request.query['resource']

	if subject != f'acct:relay@{request.host}':
		return json_response({'error': 'user not found'}, status=404)

	data = {
		'subject': subject,
		'aliases': [config.actor],
		'links': [
			{'href': config.actor, 'rel': 'self', 'type': 'application/activity+json'},
			{'href': config.actor, 'rel': 'self', 'type': 'application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"'}
		]
	}

	return json_response(data)


async def nodeinfo_2_0(request):
	data = {
		# XXX - is this valid for a relay?
		'openRegistrations': True,
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
			'peers': app['database'].hostnames
		},
		'version': '2.0'
	}

	return json_response(data)


async def nodeinfo_wellknown(request):
	data = {
		'links': [
			{
				'rel': 'http://nodeinfo.diaspora.software/ns/schema/2.0',
				'href': f'https://{request.host}/nodeinfo/2.0.json'
			}
		]
	}
	return json_response(data)


async def stats(request):
    return json_response(STATS)
