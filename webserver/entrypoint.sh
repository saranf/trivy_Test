#!/bin/bash

# Docker 소켓 권한 변경 (www-data가 접근 가능하도록)
chmod 666 /var/run/docker.sock

# PHP-FPM 실행
exec php-fpm

