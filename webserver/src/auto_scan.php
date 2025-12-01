<?php
/**
 * Docker 컨테이너 자동 스캔 API
 * - 컨테이너 시작 이벤트 감지 시 호출
 * - 모든 실행 중인 컨테이너 스캔
 * - Critical 취약점 발견시 즉시 알림
 */

// 에러를 JSON으로 출력
error_reporting(0);
ini_set('display_errors', 0);

header('Content-Type: application/json');

// 에러 핸들러
set_error_handler(function($errno, $errstr, $errfile, $errline) {
    echo json_encode(['success' => false, 'message' => "Error: $errstr"]);
    exit;
});

set_exception_handler(function($e) {
    echo json_encode(['success' => false, 'message' => 'Exception: ' . $e->getMessage()]);
    exit;
});

require_once 'db_functions.php';

// 알림 설정
$ALERT_EMAIL = getenv('ALERT_EMAIL') ?: '';  // 관리자 이메일
$ALERT_ON_CRITICAL = getenv('ALERT_ON_CRITICAL') !== 'false';  // Critical 알림 활성화

// Trivy 스캔 실행 (v0.29.2 호환)
function runTrivyScan($image, $severity = 'HIGH,CRITICAL') {
    $safeImage = escapeshellarg($image);
    $safeSeverity = escapeshellarg($severity);

    // Trivy v0.29.2: --security-checks 사용 (신버전의 --scanners 대신)
    $command = "trivy image --security-checks vuln,config --severity $safeSeverity --format json $safeImage 2>/dev/null";
    exec($command, $output, $result_code);
    
    $jsonOutput = implode("\n", $output);
    return json_decode($jsonOutput, true);
}

// 실행 중인 컨테이너 목록
function getRunningContainers() {
    $output = [];
    $result_code = 0;
    exec('docker ps --format "{{.Image}}|{{.Names}}" 2>&1', $output, $result_code);
    $containers = [];

    if ($result_code !== 0) {
        error_log("docker ps failed with code $result_code: " . implode("\n", $output));
        return $containers;
    }

    foreach ($output as $line) {
        $parts = explode('|', $line);
        if (count($parts) === 2) {
            $containers[] = [
                'image' => $parts[0],
                'name' => $parts[1]
            ];
        }
    }
    return $containers;
}

// 최근에 스캔한 이미지인지 확인 (1시간 이내)
function isRecentlyScanned($conn, $imageName, $hours = 1) {
    $stmt = $conn->prepare("SELECT id FROM scan_history WHERE image_name = ? AND scan_date > DATE_SUB(NOW(), INTERVAL ? HOUR) LIMIT 1");
    $stmt->bind_param("si", $imageName, $hours);
    $stmt->execute();
    $result = $stmt->get_result();
    $exists = $result->num_rows > 0;
    $stmt->close();
    return $exists;
}

$action = $_GET['action'] ?? '';

// scan_all은 로그인한 Operator 이상만 가능 (demo도 허용)
if ($action === 'scan_all') {
    session_start();
    if (!isset($_SESSION['user'])) {
        echo json_encode(['success' => false, 'message' => '로그인이 필요합니다.']);
        exit;
    }
    $userRole = $_SESSION['user']['role'] ?? '';
    // demo는 operator와 동일 레벨 (스캔 가능)
    $levels = ['viewer' => 1, 'demo' => 2, 'operator' => 2, 'admin' => 3];
    if (($levels[$userRole] ?? 0) < 2) {
        echo json_encode(['success' => false, 'message' => 'Operator 이상 권한이 필요합니다.']);
        exit;
    }
}

// 특정 이미지 스캔 및 저장
if ($action === 'scan_image') {
    global $ALERT_EMAIL, $ALERT_ON_CRITICAL;

    $image = $_GET['image'] ?? '';
    if (empty($image)) {
        echo json_encode(['success' => false, 'message' => '이미지명이 필요합니다.']);
        exit;
    }

    $conn = getDbConnection();
    if (!$conn) {
        echo json_encode(['success' => false, 'message' => 'DB 연결 실패']);
        exit;
    }

    initDatabase($conn);

    // 스캔 실행
    $data = runTrivyScan($image);
    if ($data === null) {
        echo json_encode(['success' => false, 'message' => '스캔 실패']);
        exit;
    }

    $scanId = saveScanResult($conn, $image, $data, 'auto');

    // Critical 취약점 체크 및 알림 발송
    $criticalCount = countCriticalVulns($data);
    $alertSent = false;

    if ($criticalCount > 0 && $ALERT_ON_CRITICAL && !empty($ALERT_EMAIL)) {
        $alertSent = sendCriticalAlert($scanId, $image, $criticalCount, $ALERT_EMAIL);
    }

    $conn->close();

    echo json_encode([
        'success' => true,
        'scanId' => $scanId,
        'image' => $image,
        'critical_count' => $criticalCount,
        'alert_sent' => $alertSent
    ]);
    exit;
}

// 모든 실행 중인 컨테이너 스캔
if ($action === 'scan_all') {
    $skipRecent = isset($_GET['skip_recent']) ? $_GET['skip_recent'] === '1' : true;
    
    $conn = getDbConnection();
    if (!$conn) {
        echo json_encode(['success' => false, 'message' => 'DB 연결 실패']);
        exit;
    }
    
    initDatabase($conn);
    
    $containers = getRunningContainers();
    $results = [];
    $scannedImages = []; // 중복 스캔 방지
    
    foreach ($containers as $container) {
        $image = $container['image'];
        
        // 이미 이번에 스캔한 이미지면 스킵
        if (in_array($image, $scannedImages)) {
            continue;
        }
        
        // 최근에 스캔한 이미지면 스킵
        if ($skipRecent && isRecentlyScanned($conn, $image)) {
            $results[] = ['image' => $image, 'status' => 'skipped', 'reason' => 'recently scanned'];
            continue;
        }
        
        $data = runTrivyScan($image);
        if ($data !== null) {
            $scanId = saveScanResult($conn, $image, $data, 'bulk');
            $results[] = ['image' => $image, 'status' => 'scanned', 'scanId' => $scanId];
            $scannedImages[] = $image;
        } else {
            $results[] = ['image' => $image, 'status' => 'failed'];
        }
    }

    // Bulk 스캔 감사 로그
    if (isset($_SESSION['user'])) {
        $scannedCount = count(array_filter($results, fn($r) => $r['status'] === 'scanned'));
        logAudit($conn, $_SESSION['user']['id'], $_SESSION['user']['username'],
                 'BULK_SCAN', 'scan', null, "scanned: {$scannedCount} images");
    }

    $conn->close();
    echo json_encode(['success' => true, 'results' => $results]);
    exit;
}

// 상태 확인
echo json_encode([
    'status' => 'ok',
    'alert_email' => $ALERT_EMAIL ?: '(not configured)',
    'alert_on_critical' => $ALERT_ON_CRITICAL,
    'endpoints' => [
        'scan_image' => '?action=scan_image&image=IMAGE_NAME',
        'scan_all' => '?action=scan_all&skip_recent=1'
    ]
]);

// =====================================================
// 헬퍼 함수들
// =====================================================

/**
 * Critical 취약점 개수 카운트
 */
function countCriticalVulns($trivyData) {
    $count = 0;
    if (isset($trivyData['Results'])) {
        foreach ($trivyData['Results'] as $result) {
            if (isset($result['Vulnerabilities'])) {
                foreach ($result['Vulnerabilities'] as $v) {
                    if (($v['Severity'] ?? '') === 'CRITICAL') {
                        $count++;
                    }
                }
            }
        }
    }
    return $count;
}

/**
 * Critical 취약점 발견 시 긴급 알림 발송
 */
function sendCriticalAlert($scanId, $imageName, $criticalCount, $toEmail) {
    $mailConfig = [
        'from' => getenv('FROM_EMAIL') ?: 'trivy-scanner@' . gethostname(),
        'fromName' => getenv('FROM_NAME') ?: 'Trivy Scanner'
    ];

    // 제목
    $subject = "🚨 [긴급] Critical 취약점 {$criticalCount}건 발견 - {$imageName}";

    // HTML 본문
    $html = '<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
        .alert-box { background: linear-gradient(135deg, #dc3545, #c82333); color: white; padding: 30px; border-radius: 8px; text-align: center; }
        .alert-icon { font-size: 48px; }
        .alert-title { font-size: 24px; margin: 15px 0; }
        .alert-count { font-size: 60px; font-weight: bold; }
        .info-box { background: #f8f9fa; padding: 20px; margin-top: 20px; border-radius: 8px; }
        .btn { display: inline-block; padding: 12px 30px; background: #007bff; color: white; text-decoration: none; border-radius: 4px; margin-top: 20px; }
    </style></head><body>';

    $html .= '<div class="alert-box">';
    $html .= '<div class="alert-icon">🚨</div>';
    $html .= '<div class="alert-title">Critical 취약점 발견</div>';
    $html .= '<div class="alert-count">' . $criticalCount . '건</div>';
    $html .= '</div>';

    $html .= '<div class="info-box">';
    $html .= '<p><strong>이미지:</strong> ' . htmlspecialchars($imageName) . '</p>';
    $html .= '<p><strong>스캔 ID:</strong> ' . $scanId . '</p>';
    $html .= '<p><strong>발생 시간:</strong> ' . date('Y-m-d H:i:s') . '</p>';
    $html .= '<p><strong>스캔 유형:</strong> 자동 스캔 (컨테이너 시작 감지)</p>';
    $html .= '</div>';

    $html .= '<p style="text-align:center;"><a href="http://monitor.rmstudio.co.kr:6987/scan_history.php" class="btn">상세 확인하기 →</a></p>';
    $html .= '<hr><p style="color:#666;font-size:12px;">이 메일은 Trivy Security Scanner에서 자동 발송되었습니다.</p>';
    $html .= '</body></html>';

    // CSV는 간단히
    $csv = "Alert Type,Image,Critical Count,Scan ID,Time\n";
    $csv .= "\"CRITICAL_ALERT\",\"{$imageName}\",{$criticalCount},{$scanId},\"" . date('Y-m-d H:i:s') . "\"";

    // 이메일 발송
    include_once 'send_email.php';
    $result = sendEmailLocal($toEmail, $subject, $html, $csv, $mailConfig);

    return $result['success'] ?? false;
}

