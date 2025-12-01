#!/bin/bash

# ==============================================
# 1️⃣ PHP Timezone 설정 (KST)
# ==============================================
echo "date.timezone = Asia/Seoul" > /usr/local/etc/php/conf.d/timezone.ini
echo "[$(date '+%Y-%m-%d %H:%M:%S')] PHP Timezone set to Asia/Seoul"

# Docker 소켓 권한 변경 (www-data가 접근 가능하도록)
chmod 666 /var/run/docker.sock

# msmtp 설치 (경량 메일 전송 에이전트)
if ! command -v msmtp &> /dev/null; then
    apt-get update && apt-get install -y msmtp msmtp-mta mailutils cron --no-install-recommends
    rm -rf /var/lib/apt/lists/*
fi

# cron 설치 확인
if ! command -v cron &> /dev/null; then
    apt-get update && apt-get install -y cron --no-install-recommends
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

# ==============================================
# 데모 환경 초기화 Cron 설정 (매일 자정 KST)
# ==============================================
echo "0 0 * * * root php /var/www/html/reset_demo.php >> /var/log/demo_reset.log 2>&1" > /etc/cron.d/demo-reset
chmod 0644 /etc/cron.d/demo-reset
crontab /etc/cron.d/demo-reset

# 주기적 스캔 실행 Cron (매 5분마다)
echo "*/5 * * * * root curl -s http://localhost/run_scheduled_scans_api.php >> /var/log/scheduled_scans.log 2>&1" > /etc/cron.d/scheduled-scans
chmod 0644 /etc/cron.d/scheduled-scans

# Cron 서비스 시작
service cron start

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Cron jobs configured:"
echo "  - Demo reset: 매일 자정 (KST)"
echo "  - Scheduled scans: 매 5분"

# PHP-FPM 실행
exec php-fpm

