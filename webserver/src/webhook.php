<?php
/**
 * 🔔 Slack Webhook 알림 기능
 * - 스캔 결과 알림
 * - Critical 취약점 발견 시 즉시 알림
 */

// Webhook 설정
define('SLACK_WEBHOOK_URL', getenv('SLACK_WEBHOOK_URL') ?: '');
define('SLACK_CHANNEL', getenv('SLACK_CHANNEL') ?: '#security-alerts');
define('SLACK_USERNAME', getenv('SLACK_USERNAME') ?: 'Trivy Scanner');

/**
 * Slack 메시지 전송
 */
function sendSlackNotification($message, $attachments = [], $channel = null) {
    if (empty(SLACK_WEBHOOK_URL)) {
        return ['success' => false, 'error' => 'SLACK_WEBHOOK_URL이 설정되지 않았습니다.'];
    }

    $payload = [
        'channel' => $channel ?: SLACK_CHANNEL,
        'username' => SLACK_USERNAME,
        'icon_emoji' => ':shield:',
        'text' => $message
    ];

    if (!empty($attachments)) {
        $payload['attachments'] = $attachments;
    }

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => SLACK_WEBHOOK_URL,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode($payload),
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_TIMEOUT => 10
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);

    if ($error) {
        return ['success' => false, 'error' => "cURL 오류: $error"];
    }

    return [
        'success' => $httpCode === 200,
        'error' => $httpCode !== 200 ? "HTTP $httpCode: $response" : null
    ];
}

/**
 * 스캔 결과 알림 (Critical/High 취약점 발견 시)
 */
function sendScanAlert($imageName, $criticalCount, $highCount, $totalVulns, $scanSource = 'auto') {
    if ($criticalCount == 0 && $highCount == 0) {
        return ['success' => true, 'skipped' => true, 'reason' => 'No critical/high vulnerabilities'];
    }

    $severity = $criticalCount > 0 ? 'danger' : 'warning';
    $emoji = $criticalCount > 0 ? '🚨' : '⚠️';
    $sourceLabel = [
        'auto' => '자동 스캔',
        'manual' => '수동 스캔',
        'scheduled' => '주기적 스캔',
        'bulk' => '일괄 스캔'
    ][$scanSource] ?? $scanSource;

    $message = "$emoji *취약점 발견 알림*";

    $attachments = [
        [
            'color' => $severity,
            'title' => "📦 $imageName",
            'fields' => [
                ['title' => '🔴 CRITICAL', 'value' => (string)$criticalCount, 'short' => true],
                ['title' => '🟠 HIGH', 'value' => (string)$highCount, 'short' => true],
                ['title' => '📊 총 취약점', 'value' => (string)$totalVulns, 'short' => true],
                ['title' => '📋 스캔 유형', 'value' => $sourceLabel, 'short' => true]
            ],
            'footer' => 'Trivy Scanner',
            'ts' => time()
        ]
    ];

    return sendSlackNotification($message, $attachments);
}

/**
 * 스캔 완료 요약 알림 (일괄/전체 스캔용)
 */
function sendBulkScanSummary($scannedCount, $totalCritical, $totalHigh, $failedCount = 0) {
    $severity = $totalCritical > 0 ? 'danger' : ($totalHigh > 0 ? 'warning' : 'good');
    $emoji = $totalCritical > 0 ? '🚨' : ($totalHigh > 0 ? '⚠️' : '✅');

    $message = "$emoji *일괄 스캔 완료*";

    $attachments = [
        [
            'color' => $severity,
            'title' => "📊 스캔 요약",
            'fields' => [
                ['title' => '✅ 스캔 완료', 'value' => "{$scannedCount}개 이미지", 'short' => true],
                ['title' => '❌ 실패', 'value' => "{$failedCount}개", 'short' => true],
                ['title' => '🔴 CRITICAL 합계', 'value' => (string)$totalCritical, 'short' => true],
                ['title' => '🟠 HIGH 합계', 'value' => (string)$totalHigh, 'short' => true]
            ],
            'footer' => 'Trivy Scanner',
            'ts' => time()
        ]
    ];

    return sendSlackNotification($message, $attachments);
}

/**
 * 커스텀 메시지 전송 (Diff 리포트 등)
 */
function sendCustomSlackMessage($title, $text, $severity = 'info') {
    $colorMap = [
        'danger' => 'danger',
        'warning' => 'warning',
        'good' => 'good',
        'info' => '#36a64f'
    ];

    $attachments = [
        [
            'color' => $colorMap[$severity] ?? '#36a64f',
            'title' => $title,
            'text' => $text,
            'footer' => 'Trivy Scanner',
            'ts' => time()
        ]
    ];

    return sendSlackNotification('', $attachments);
}

/**
 * Webhook 설정 상태 확인
 */
function isWebhookConfigured() {
    return !empty(SLACK_WEBHOOK_URL);
}

// API 엔드포인트 처리
if (isset($_GET['action'])) {
    header('Content-Type: application/json');
    session_start();

    // 로그인 확인
    if (!isset($_SESSION['user'])) {
        echo json_encode(['success' => false, 'error' => '로그인이 필요합니다.']);
        exit;
    }

    $action = $_GET['action'];

    if ($action === 'test') {
        // Admin만 테스트 가능
        if (($_SESSION['user']['role'] ?? '') !== 'admin') {
            echo json_encode(['success' => false, 'error' => 'Admin 권한이 필요합니다.']);
            exit;
        }

        if (!isWebhookConfigured()) {
            echo json_encode(['success' => false, 'error' => 'SLACK_WEBHOOK_URL이 설정되지 않았습니다.']);
            exit;
        }

        $result = sendCustomSlackMessage(
            "🧪 테스트 알림",
            "Trivy Scanner Webhook 연결 테스트입니다.\n발송자: " . ($_SESSION['user']['username'] ?? 'unknown'),
            'good'
        );

        echo json_encode($result);
        exit;
    }

    if ($action === 'status') {
        echo json_encode([
            'configured' => isWebhookConfigured(),
            'channel' => SLACK_CHANNEL
        ]);
        exit;
    }

    echo json_encode(['success' => false, 'error' => '알 수 없는 액션']);
    exit;
}

