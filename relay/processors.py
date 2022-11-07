import asyncio
import logging

from uuid import uuid4

from . import app, misc


async def handle_relay(request, actor, data, software):
	cache = app['cache'].objects
	config = app['config']

	if data.objectid in cache:
		logging.verbose(f'already relayed {data.objectid} as {cache[data.objectid]}')
		return

	logging.verbose(f'Relaying post from {data.actorid}')

	message = misc.Message.new_announce(
		host = config.host,
		object = data.objectid
	)

	logging.debug(f'>> relay: {message}')

	inboxes = misc.distill_inboxes(actor, data.objectid)
	futures = [misc.request(inbox, data=message) for inbox in inboxes]

	asyncio.ensure_future(asyncio.gather(*futures))
	cache[data.objectid] = message.id


async def handle_forward(request, actor, data, software):
	cache = app['cache'].objects
	config = app['config']

	if data.id in cache:
		logging.verbose(f'already forwarded {data.id}')
		return

	message = misc.Message.new_announce(
		host = config.host,
		object = data
	)

	logging.verbose(f'Forwarding post from {actor.id}')
	logging.debug(f'>> Relay {data}')

	inboxes = misc.distill_inboxes(actor, data.id)
	futures = [misc.request(inbox, data=message) for inbox in inboxes]

	asyncio.ensure_future(asyncio.gather(*futures))
	cache[data.id] = message.id


async def handle_follow(request, actor, data, software):
	config = app['config']
	database = app['database']

	if database.add_inbox(inbox, data.id):
		database.set_followid(actor.id, data.id)

	database.save()

	await misc.request(
		actor.shared_inbox,
		misc.Message.new_response(
			host = config.host,
			actor = actor.id,
			followid = data.id,
			accept = True
		)
	)

	# Are Akkoma and Pleroma the only two that expect a follow back?
	# Ignoring only Mastodon for now
	if software != 'mastodon':
		misc.request(
			actor.shared_inbox,
			misc.Message.new_follow(
				host = config.host,
				actor = actor.id
			)
		)


async def handle_undo(request, actor, data, software):
	## If the object is not a Follow, forward it
	if data['object']['type'] != 'Follow':
		return await handle_forward(request, actor, data, software)

	database = app['database']

	if not database.del_inbox(actor.domain, data.id):
		return

	database.save()

	message = misc.Message.new_unfollow(
		host = config.host,
		actor = actor.id,
		follow = data
	)

	await misc.request(actor.shared_inbox, message)


processors = {
	'Announce': handle_relay,
	'Create': handle_relay,
	'Delete': handle_forward,
	'Follow': handle_follow,
	'Undo': handle_undo,
	'Update': handle_forward,
}


async def run_processor(request, actor, data, software):
	if data.type not in processors:
		return

	logging.verbose(f'New "{data.type}" from actor: {actor.id}')
	return await processors[data.type](request, actor, data, software)
