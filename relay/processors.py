import asyncio
import logging

from uuid import uuid4

from . import app, misc


async def handle_relay(actor, data, request):
	cache = app['cache'].objects
	object_id = misc.distill_object_id(data)

	if object_id in cache:
		logging.verbose(f'already relayed {object_id} as {cache[object_id]}')
		return

	logging.verbose(f'Relaying post from {actor["id"]}')

	activity_id = f"https://{request.host}/activities/{uuid4()}"

	message = {
		"@context": "https://www.w3.org/ns/activitystreams",
		"type": "Announce",
		"to": [f"https://{request.host}/followers"],
		"actor": f"https://{request.host}/actor",
		"object": object_id,
		"id": activity_id
	}

	logging.debug(f'>> relay: {message}')

	inboxes = misc.distill_inboxes(actor, object_id)
	futures = [misc.request(inbox, data=message) for inbox in inboxes]

	asyncio.ensure_future(asyncio.gather(*futures))
	cache[object_id] = activity_id


async def handle_forward(actor, data, request):
	cache = app['cache'].objects
	object_id = data['id']

	if object_id in cache:
		logging.verbose(f'already forwarded {object_id}')
		return

	activity_id = f"https://{request.host}/activities/{uuid4()}"

	message = {
		"@context": "https://www.w3.org/ns/activitystreams",
		"type": "Announce",
		"to": [f"https://{request.host}/followers"],
		"actor": f"https://{request.host}/actor",
		"object": data,
		"id": activity_id
	}

	logging.verbose(f'Forwarding post from {actor["id"]}')
	logging.debug(f'>> Relay {data}')

	inboxes = misc.distill_inboxes(actor, object_id)

	futures = [misc.request(inbox, data=message) for inbox in inboxes]
	asyncio.ensure_future(asyncio.gather(*futures))

	cache[object_id] = activity_id


async def handle_follow(actor, data, request):
	config = app['config']
	database = app['database']

	inbox = misc.get_actor_inbox(actor)
	dbinbox = database.get_inbox(inbox)

	if not database.add_inbox(inbox, data['id']):
		database.set_followid(inbox, data['id'])
		database.save()

	asyncio.ensure_future(misc.follow_remote_actor(actor['id']))

	message = {
		"@context": "https://www.w3.org/ns/activitystreams",
		"type": "Accept",
		"to": [actor["id"]],
		"actor": config.actor,

		# this is wrong per litepub, but mastodon < 2.4 is not compliant with that profile.
		"object": {
			"type": "Follow",
			"id": data["id"],
			"object": config.actor,
			"actor": actor["id"]
		},

		"id": f"https://{request.host}/activities/{uuid4()}",
	}

	asyncio.ensure_future(misc.request(inbox, message))


async def handle_undo(actor, data, request):
	## If the object is not a Follow, forward it
	if data['object']['type'] != 'Follow':
		return await handle_forward(actor, data, request)

	database = app['database']
	objectid = misc.distill_object_id(data)

	if not database.del_inbox(actor['id'], objectid):
		return

	database.save()

	await misc.unfollow_remote_actor(actor['id'])


processors = {
	'Announce': handle_relay,
	'Create': handle_relay,
	'Delete': handle_forward,
	'Follow': handle_follow,
	'Undo': handle_undo,
	'Update': handle_forward,
}


async def run_processor(request, data, actor):
	if data['type'] not in processors:
		return

	logging.verbose(f'New activity from actor: {actor["id"]} {data["type"]}')
	return await processors[data['type']](actor, data, request)
