#!/bin/bash

# Docker 소켓 권한 변경 (www-data가 접근 가능하도록)
chmod 666 /var/run/docker.sock

# msmtp 설치 (경량 메일 전송 에이전트)
if ! command -v msmtp &> /dev/null; then
    apt-get update && apt-get install -y msmtp msmtp-mta mailutils --no-install-recommends
    rm -rf /var/lib/apt/lists/*
fi

# msmtp 설정 파일 생성 (postfix 컨테이너 사용)
cat > /etc/msmtprc << 'EOF'
defaults
auth           off
tls            off
tls_starttls   off
logfile        /var/log/msmtp.log

account        default
host           mailserver
port           25
from           trivy-scanner@monitor.rmstudio.co.kr
EOF

chmod 644 /etc/msmtprc

# PHP sendmail 경로 설정
echo "sendmail_path = /usr/bin/msmtp -t" > /usr/local/etc/php/conf.d/mail.ini

# PHP-FPM 실행
exec php-fpm

