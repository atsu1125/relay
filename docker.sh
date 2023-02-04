#!/usr/bin/env bash

case $1 in
	install)
		docker build -f Dockerfile -t activityrelay . && \
		docker volume create activityrelay-data && \
		docker run -it -p 8080:8080 -v activityrelay-data:/data --name activityrelay activityrelay
	;;

	uninstall)
		docker stop activityrelay && \
		docker container rm activityrelay && \
		docker volume rm activityrelay-data && \
		docker image rm activityrelay
	;;

	start)
		docker start activityrelay
	;;

	stop)
		docker stop activityrelay
	;;

	manage)
		shift
		docker exec -it activityrelay python3 -m relay "$@"
	;;

	shell)
		docker exec -it activityrelay bash
	;;

	rescue)
		docker run -it --rm --entrypoint bash -v activityrelay-data:/data activityrelay
	;;

	edit)
		if [ -z ${EDITOR} ]; then
			echo "EDITOR environmental variable not set"
			exit
		fi

		CONFIG="/tmp/relay-$(date +"%T").yaml"

		docker cp activityrelay:/data/relay.yaml $CONFIG && \
		$EDITOR $CONFIG && \

		docker cp $CONFIG activityrelay:/data/relay.yaml && \
		rm $CONFIG
	;;

	*)
		COLS="%-22s %s\n"

		echo "Valid commands:"
		printf "$COLS" "- start" "Run the relay in the background"
		printf "$COLS" "- stop" "Stop the relay"
		printf "$COLS" "- manage <cmd> [args]" "Run a relay management command"
		printf "$COLS" "- edit" "Edit the relay's config in \$EDITOR"
		printf "$COLS" "- shell" "Drop into a bash shell on the running container"
		printf "$COLS" "- rescue" "Drop into a bash shell on a temp container with the data volume mounted"
		printf "$COLS" "- install" "Build the image, create a new container and volume, and run relay setup"
		printf "$COLS" "- uninstall" "Delete the relay image, container, and volume"
	;;
esac
