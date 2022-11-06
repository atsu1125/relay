import asyncio
import base64
import json
import logging
import socket
import traceback

from Crypto.Hash import SHA, SHA256, SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from aiohttp import ClientSession
from datetime import datetime
from json.decoder import JSONDecodeError
from urllib.parse import urlparse
from uuid import uuid4

from . import app
from .http_debug import http_debug


HASHES = {
	'sha1': SHA,
	'sha256': SHA256,
	'sha512': SHA512
}


def build_signing_string(headers, used_headers):
	return '\n'.join(map(lambda x: ': '.join([x.lower(), headers[x]]), used_headers))


def check_open_port(host, port):
	if host == '0.0.0.0':
		host = '127.0.0.1'

	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		try:
			return s.connect_ex((host , port)) != 0

		except socket.error as e:
			return False


def create_signature_header(headers):
	headers = {k.lower(): v for k, v in headers.items()}
	used_headers = headers.keys()
	sigstring = build_signing_string(headers, used_headers)

	sig = {
		'keyId': app['config'].keyid,
		'algorithm': 'rsa-sha256',
		'headers': ' '.join(used_headers),
		'signature': sign_signing_string(sigstring, app['database'].PRIVKEY)
	}

	chunks = ['{}="{}"'.format(k, v) for k, v in sig.items()]
	return ','.join(chunks)


def distill_object_id(activity):
	logging.debug(f'>> determining object ID for {activity["object"]}')

	try:
		return activity['object']['id']

	except TypeError:
		return activity['object']


def distill_inboxes(actor, object_id):
	database = app['database']
	origin_hostname = urlparse(object_id).hostname
	actor_inbox = get_actor_inbox(actor)
	targets = []

	for inbox in database.inboxes:
		if inbox != actor_inbox or urlparse(inbox).hostname != origin_hostname:
			targets.append(inbox)

	return targets


def generate_body_digest(body):
	bodyhash = app['cache'].digests.get(body)

	if bodyhash:
		return bodyhash

	h = SHA256.new(body.encode('utf-8'))
	bodyhash = base64.b64encode(h.digest()).decode('utf-8')
	app['cache'].digests[body] = bodyhash

	return bodyhash


def get_actor_inbox(actor):
	return actor.get('endpoints', {}).get('sharedInbox', actor['inbox'])


def sign_signing_string(sigstring, key):
	pkcs = PKCS1_v1_5.new(key)
	h = SHA256.new()
	h.update(sigstring.encode('ascii'))
	sigdata = pkcs.sign(h)

	return base64.b64encode(sigdata).decode('utf-8')


def split_signature(sig):
	default = {"headers": "date"}

	sig = sig.strip().split(',')

	for chunk in sig:
		k, _, v = chunk.partition('=')
		v = v.strip('\"')
		default[k] = v

	default['headers'] = default['headers'].split()
	return default


async def fetch_actor_key(actor):
	actor_data = await request(actor)

	if not actor_data:
		return None

	try:
		return RSA.importKey(actor_data['publicKey']['publicKeyPem'])

	except Exception as e:
		logging.debug(f'Exception occured while fetching actor key: {e}')


async def fetch_nodeinfo(domain):
	nodeinfo_url = None

	wk_nodeinfo = await request(f'https://{domain}/.well-known/nodeinfo', sign_headers=False, activity=False)

	if not wk_nodeinfo:
		return

	for link in wk_nodeinfo.get('links', ''):
		if link['rel'] == 'http://nodeinfo.diaspora.software/ns/schema/2.0':
			nodeinfo_url = link['href']
			break

	if not nodeinfo_url:
		return

	nodeinfo_data = await request(nodeinfo_url, sign_headers=False, activity=False)

	try:
		return nodeinfo_data['software']['name']

	except KeyError:
		return False


async def follow_remote_actor(actor_uri):
	config = app['config']

	actor = await request(actor_uri)
	inbox = get_actor_inbox(actor)

	if not actor:
		logging.error(f'failed to fetch actor at: {actor_uri}')
		return

	logging.verbose(f'sending follow request: {actor_uri}')

	message = {
		"@context": "https://www.w3.org/ns/activitystreams",
		"type": "Follow",
		"to": [actor['id']],
		"object": actor['id'],
		"id": f"https://{config.host}/activities/{uuid4()}",
		"actor": f"https://{config.host}/actor"
	}

	await request(inbox, message)


async def unfollow_remote_actor(actor_uri):
	config = app['config']

	actor = await request(actor_uri)

	if not actor:
		logging.error(f'failed to fetch actor: {actor_uri}')
		return

	inbox = get_actor_inbox(actor)
	logging.verbose(f'sending unfollow request to inbox: {inbox}')

	message = {
		"@context": "https://www.w3.org/ns/activitystreams",
		"type": "Undo",
		"to": [actor_uri],
		"object": {
			"type": "Follow",
			"object": actor_uri,
			"actor": actor_uri,
			"id": f"https://{config.host}/activities/{uuid4()}"
		},
		"id": f"https://{config.host}/activities/{uuid4()}",
		"actor": f"https://{config.host}/actor"
	}

	await request(inbox, message)


async def request(uri, data=None, force=False, sign_headers=True, activity=True):
	## If a get request and not force, try to use the cache first
	if not data and not force:
		try:
			return app['cache'].json[uri]

		except KeyError:
			pass

	url = urlparse(uri)
	method = 'POST' if data else 'GET'
	action = data.get('type') if data else None
	headers = {
		'Accept': 'application/activity+json, application/json;q=0.9',
		'User-Agent': 'ActivityRelay',
	}

	if data:
		headers['Content-Type'] = 'application/activity+json' if activity else 'application/json'

	if sign_headers:
		signing_headers = {
			'(request-target)': f'{method.lower()} {url.path}',
			'Date': datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT'),
			'Host': url.netloc
		}

		if data:
			assert isinstance(data, dict)

			data = json.dumps(data)
			signing_headers.update({
				'Digest': f'SHA-256={generate_body_digest(data)}',
				'Content-Length': str(len(data.encode('utf-8')))
			})

		signing_headers['Signature'] = create_signature_header(signing_headers)

		del signing_headers['(request-target)']
		del signing_headers['Host']

		headers.update(signing_headers)

	try:
		async with ClientSession(trace_configs=http_debug()) as session, app['semaphore']:
			async with session.request(method, uri, headers=headers, data=data) as resp:
				## aiohttp has been known to leak if the response hasn't been read,
				## so we're just gonna read the request no matter what
				resp_data = await resp.json()

				if resp.status not in [200, 202]:
					if not resp_data:
						logging.verbose(f'Received error when requesting {uri}: {resp.status} {resp_data}')
						return

					logging.verbose(f'Received error when sending {action} to {uri}: {resp.status} {resp_data}')
					return

				logging.debug(f'{uri} >> resp {resp_data}')

				app['cache'].json[uri] = resp_data
				return resp_data

	except JSONDecodeError:
		return

	except Exception:
		traceback.print_exc()


async def validate_signature(actor, http_request):
	pubkey = await fetch_actor_key(actor)

	if not pubkey:
		return False

	logging.debug(f'actor key: {pubkey}')

	headers = {key.lower(): value for key, value in http_request.headers.items()}
	headers['(request-target)'] = ' '.join([http_request.method.lower(), http_request.path])

	sig = split_signature(headers['signature'])
	logging.debug(f'sigdata: {sig}')

	sigstring = build_signing_string(headers, sig['headers'])
	logging.debug(f'sigstring: {sigstring}')

	sign_alg, _, hash_alg = sig['algorithm'].partition('-')
	logging.debug(f'sign alg: {sign_alg}, hash alg: {hash_alg}')

	sigdata = base64.b64decode(sig['signature'])

	pkcs = PKCS1_v1_5.new(pubkey)
	h = HASHES[hash_alg].new()
	h.update(sigstring.encode('ascii'))
	result = pkcs.verify(h, sigdata)

	http_request['validated'] = result

	logging.debug(f'validates? {result}')
	return result
