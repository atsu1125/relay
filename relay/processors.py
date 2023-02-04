import asyncio
import logging

from cachetools import LRUCache
from uuid import uuid4

from .misc import Message


cache = LRUCache(1024)


def person_check(actor, software):
	## pleroma and akkoma may use Person for the actor type for some reason
	if software in {'akkoma', 'pleroma'} and actor.id == f'https://{actor.domain}/relay':
		return False

	## make sure the actor is an application
	if actor.type != 'Application':
		return True


async def handle_relay(request):
	if request.message.objectid in cache:
		logging.verbose(f'already relayed {request.message.objectid}')
		return

	message = Message.new_announce(
		host = request.config.host,
		object = request.message.objectid
	)

	cache[request.message.objectid] = message.id
	logging.debug(f'>> relay: {message}')

	inboxes = request.database.distill_inboxes(request.message)

	for inbox in inboxes:
		request.app.push_message(inbox, message)


async def handle_forward(request):
	if request.message.id in cache:
		logging.verbose(f'already forwarded {request.message.id}')
		return

	message = Message.new_announce(
		host = request.config.host,
		object = request.message
	)

	cache[request.message.id] = message.id
	logging.debug(f'>> forward: {message}')

	inboxes = request.database.distill_inboxes(request.message)

	for inbox in inboxes:
		request.app.push_message(inbox, message)


async def handle_follow(request):
	nodeinfo = await request.app.client.fetch_nodeinfo(request.actor.domain)
	software = nodeinfo.sw_name if nodeinfo else None

	## reject if software used by actor is banned
	if request.config.is_banned_software(software):
		request.app.push_message(
			request.actor.shared_inbox,
			Message.new_response(
				host = request.config.host,
				actor = request.actor.id,
				followid = request.message.id,
				accept = False
			)
		)

		return logging.verbose(f'Rejected follow from actor for using specific software: actor={request.actor.id}, software={software}')

	## reject if the actor is not an instance actor
	if person_check(request.actor, software):
		request.app.push_message(
			request.actor.shared_inbox,
			Message.new_response(
				host = request.config.host,
				actor = request.actor.id,
				followid = request.message.id,
				accept = False
			)
		)

		return logging.verbose(f'Non-application actor tried to follow: {request.actor.id}')

	request.database.add_inbox(request.actor.shared_inbox, request.message.id, software)
	request.database.save()

	request.app.push_message(
		request.actor.shared_inbox,
		Message.new_response(
			host = request.config.host,
			actor = request.actor.id,
			followid = request.message.id,
			accept = True
		)
	)

	# Are Akkoma and Pleroma the only two that expect a follow back?
	# Ignoring only Mastodon for now
	if software != 'mastodon':
		request.app.push_message(
			request.actor.shared_inbox,
			Message.new_follow(
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

	request.app.push_message(
		request.actor.shared_inbox,
		Message.new_unfollow(
			host = request.config.host,
			actor = request.actor.id,
			follow = request.message
		)
	)


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

	if request.instance and not request.instance.get('software'):
		nodeinfo = await request.app.client.fetch_nodeinfo(request.instance['domain'])

		if nodeinfo:
			request.instance['software'] = nodeinfo.sw_name
			request.database.save()

	logging.verbose(f'New "{request.message.type}" from actor: {request.actor.id}')
	return await processors[request.message.type](request)
