#!/bin/sh

czertainlyHome="/opt/czertainly"
source ${czertainlyHome}/static-functions

log "INFO" "Launching the Cryptosense Discovery Provider"
java $JAVA_OPTS -jar ./app.jar

#exec "$@"