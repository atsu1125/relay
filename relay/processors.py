import asyncio
import logging

from uuid import uuid4

from . import misc


async def handle_relay(request):
	if request.message.objectid in request.cache.objects:
		logging.verbose(f'already relayed {request.message.objectid}')
		return

	logging.verbose(f'Relaying post from {request.message.actorid}')

	message = misc.Message.new_announce(
		host = request.config.host,
		object = request.message.objectid
	)

	logging.debug(f'>> relay: {message}')

	inboxes = misc.distill_inboxes(request.actor, request.message.objectid)
	futures = [misc.request(inbox, data=message) for inbox in inboxes]

	asyncio.ensure_future(asyncio.gather(*futures))
	request.cache.objects[request.message.objectid] = message.id


async def handle_forward(request):
	if request.message.id in request.cache.objects:
		logging.verbose(f'already forwarded {request.message.id}')
		return

	message = misc.Message.new_announce(
		host = request.config.host,
		object = request.message
	)

	logging.verbose(f'Forwarding post from {request.actor.id}')
	logging.debug(f'>> Relay {request.message}')

	inboxes = misc.distill_inboxes(request.actor, request.message.id)
	futures = [misc.request(inbox, data=message) for inbox in inboxes]

	asyncio.ensure_future(asyncio.gather(*futures))
	request.cache.objects[request.message.id] = message.id


async def handle_follow(request):
	nodeinfo = await misc.fetch_nodeinfo(request.actor.domain)
	software = nodeinfo.swname if nodeinfo else None

	## reject if software used by actor is banned
	if request.config.is_banned_software(software):
		return logging.verbose(f'Rejected follow from actor for using specific software: actor={request.actor.id}, software={software}')

	request.database.add_inbox(request.actor.shared_inbox, request.message.id, software)
	request.database.save()

	await misc.request(
		request.actor.shared_inbox,
		misc.Message.new_response(
			host = request.config.host,
			actor = request.actor.id,
			followid = request.message.id,
			accept = True
		)
	)

	# Are Akkoma and Pleroma the only two that expect a follow back?
	# Ignoring only Mastodon for now
	if software != 'mastodon':
		await misc.request(
			request.actor.shared_inbox,
			misc.Message.new_follow(
				host = request.config.host,
				actor = request.actor.id
			)
		)


async def handle_undo(request):
	## If the object is not a Follow, forward it
	if request.message.object.type != 'Follow':
		return await handle_forward(request)

	if not request.database.del_inbox(request.actor.domain, request.message.id):
		return

	request.database.save()

	message = misc.Message.new_unfollow(
		host = request.config.host,
		actor = request.actor.id,
		follow = request.message
	)

	await misc.request(request.actor.shared_inbox, message)


processors = {
	'Announce': handle_relay,
	'Create': handle_relay,
	'Delete': handle_forward,
	'Follow': handle_follow,
	'Undo': handle_undo,
	'Update': handle_forward,
}


async def run_processor(request):
	if request.message.type not in processors:
		return

	logging.verbose(f'New "{request.message.type}" from actor: {request.actor.id}')
	return await processors[request.message.type](request)
