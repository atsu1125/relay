# Installation

There are a few ways to install ActivityRelay. Follow one of the methods below, setup a reverse
proxy, and setup the relay to run via a supervisor. Example configs for caddy, nginx, and systemd
in `installation/`


## Pipx

Pipx uses pip and a custom venv implementation to automatically install modules into a Python
environment and is the recommended method. Install pipx if it isn't installed already. Check out
the [official pipx docs](https://pypa.github.io/pipx/installation/) for more in-depth instructions.

	python3 -m pip install pipx

Now simply install ActivityRelay directly from git

	pipx install git+https://git.pleroma.social/pleroma/relay@0.2.4

Or from a cloned git repo.

	pipx install .

Once finished, you can set up the relay via the setup command. It will ask a few questions to fill
out config options for your relay

	~/.local/bin/activityrelay setup

Finally start it up with the run command.

	~/.local/bin/activityrelay run

Note: Pipx requires python 3.7+. If your distro doesn't have a compatible version of python, it can
be installed via [pyenv](https://github.com/pyenv/pyenv).


## Pip

The instructions for installation via pip are very similar to pipx. Installation can be done from
git

	python3 -m pip install git+https://git.pleroma.social/pleroma/relay@0.2.4

or a cloned git repo.

	python3 -m pip install .

Now run the configuration wizard

	python3 -m relay setup

And start the relay when finished

	python3 -m relay run


## Docker

Installation and management via Docker can be handled with the `docker.sh` script. To install
ActivityRelay, run the install command. Once the image is built and the container is created,
your will be asked to fill out some config options for your relay.

	./docker.sh install

Finally start it up. It will be listening on TCP port 8080.

	./docker.sh start
