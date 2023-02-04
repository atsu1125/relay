import logging
import os

from pathlib import Path


## Add the verbose logging level
def verbose(message, *args, **kwargs):
	if not logging.root.isEnabledFor(logging.VERBOSE):
		return

	logging.log(logging.VERBOSE, message, *args, **kwargs)

setattr(logging, 'verbose', verbose)
setattr(logging, 'VERBOSE', 15)
logging.addLevelName(15, 'VERBOSE')


## Get log level and file from environment if possible
env_log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()

try:
	env_log_file = Path(os.environ.get('LOG_FILE')).expanduser().resolve()

except TypeError:
	env_log_file = None


## Make sure the level from the environment is valid
try:
	log_level = getattr(logging, env_log_level)

except AttributeError:
	log_level = logging.INFO


## Set logging config
handlers = [logging.StreamHandler()]

if env_log_file:
	handlers.append(logging.FileHandler(env_log_file))

logging.basicConfig(
	level = log_level,
	format = "[%(asctime)s] %(levelname)s: %(message)s",
	handlers = handlers
)
