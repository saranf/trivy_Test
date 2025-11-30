FROM alpine:3.18

RUN apk add --no-cache docker-cli curl bash

COPY auto_scan_daemon.sh /auto_scan_daemon.sh
RUN chmod +x /auto_scan_daemon.sh

CMD ["/auto_scan_daemon.sh"]

