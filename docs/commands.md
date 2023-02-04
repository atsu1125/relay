# Commands

There are a number of commands to manage your relay's database and config. You can add `--help` to
any category or command to get help on that specific option (ex. `activityrelay inbox --help`).

Note: Unless specified, it is recommended to run any commands while the relay is shutdown.

Note 2: `activityrelay` is only available via pip or pipx if `~/.local/bin` is in `$PATH`. If it
isn't, use `python3 -m relay` if installed via pip or `~/.local/bin/activityrelay` if installed
via pipx


## Run

Run the relay.

	activityrelay run


## Setup

Run the setup wizard to configure your relay.

	activityrelay setup


## Config

Manage the relay config

	activityrelay config


### List

List the current config key/value pairs

	activityrelay config list


### Set

Set a value for a config option

	activityrelay config set <key> <value>


## Inbox

Manage the list of subscribed instances.


### List

List the currently subscribed instances or relays.

	activityrelay inbox list


### Add

Add an inbox to the database. If a domain is specified, it will default to `https://{domain}/inbox`.
If the added instance is not following the relay, expect errors when pushing messages.

	activityrelay inbox add <inbox or domain>


### Remove

Remove an inbox from the database. An inbox or domain can be specified.

	activityrelay inbox remove <inbox or domain>


### Follow

Follow an instance or relay actor and add it to the database. If a domain is specified, it will
default to `https://{domain}/actor`.

	activityrelay inbox follow <actor or domain>

Note: The relay must be running for this command to work.


### Unfollow

Unfollow an instance or relay actor and remove it from the database. If the instance or relay does
not exist anymore, use the `inbox remove` command instead.

	activityrelay inbox unfollow <domain, actor, or inbox>

Note: The relay must be running for this command to work.


## Whitelist

Manage the whitelisted domains.


### List

List the current whitelist.

	activityrelay whitelist list


### Add

Add a domain to the whitelist.

	activityrelay whitelist add <domain>


### Remove

Remove a domain from the whitelist.

	activityrelay whitelist remove <domain>


### Import

Add all current inboxes to the whitelist

	activityrelay whitelist import


## Instance

Manage the instance ban list.


### List

List the currently banned instances

	activityrelay instance list


### Ban

Add an instance to the ban list. If the instance is currently subscribed, remove it from the
database. 

	activityrelay instance ban <domain>


### Unban

Remove an instance from the ban list.

	activityrelay instance unban <domain>


## Software

Manage the software ban list. To get the correct name, check the software's nodeinfo endpoint.
You can find it at nodeinfo\['software']\['name'].


### List

List the currently banned software.

	activityrelay software list


### Ban

Add a software name to the ban list.

If `-f` or `--fetch-nodeinfo` is set, treat the name as a domain and try to fetch the software
name via nodeinfo.

If the name is `RELAYS` (case-sensitive), add all known relay software names to the list.

	activityrelay software ban [-f/--fetch-nodeinfo] <name, domain, or RELAYS>


### Unban

Remove a software name from the ban list.

If `-f` or `--fetch-nodeinfo` is set, treat the name as a domain and try to fetch the software
name via nodeinfo.

If the name is `RELAYS` (case-sensitive), remove all known relay software names from the list.

	activityrelay unban [-f/--fetch-nodeinfo] <name, domain, or RELAYS>
