<?php
/**
 * 데모 환경 초기화 스크립트
 * - 매일 자정(KST)에 cron으로 실행
 * - 오래된 스캔 데이터 삭제
 * - 감사 로그 정리
 * - demo 계정 재생성
 * 
 * 실행: php /var/www/html/reset_demo.php
 * 또는: curl http://localhost/reset_demo.php?key=RESET_SECRET_KEY
 */

// CLI 또는 인증된 요청만 허용
$isCliMode = php_sapi_name() === 'cli';
$secretKey = getenv('DEMO_RESET_KEY') ?: 'trivy_demo_reset_2024';

if (!$isCliMode) {
    $providedKey = $_GET['key'] ?? '';
    if ($providedKey !== $secretKey) {
        http_response_code(403);
        die('Forbidden');
    }
}

require_once __DIR__ . '/db_functions.php';

$conn = getDbConnection();
$results = [];
$timestamp = date('Y-m-d H:i:s');

echo "=== 데모 환경 초기화 시작: $timestamp ===\n\n";

try {
    // 1. 7일 이상 된 스캔 기록 삭제
    $stmt = $conn->prepare("DELETE FROM scan_vulnerabilities WHERE scan_id IN (SELECT id FROM scan_history WHERE scanned_at < DATE_SUB(NOW(), INTERVAL 7 DAY))");
    $stmt->execute();
    $deletedVulns = $stmt->affected_rows;
    $stmt->close();
    
    $stmt = $conn->prepare("DELETE FROM scan_history WHERE scanned_at < DATE_SUB(NOW(), INTERVAL 7 DAY)");
    $stmt->execute();
    $deletedScans = $stmt->affected_rows;
    $stmt->close();
    $results[] = "✅ 7일 이상 된 스캔 기록 삭제: {$deletedScans}건 (취약점: {$deletedVulns}건)";

    // 2. 30일 이상 된 감사 로그 삭제
    $stmt = $conn->prepare("DELETE FROM audit_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY)");
    $stmt->execute();
    $deletedLogs = $stmt->affected_rows;
    $stmt->close();
    $results[] = "✅ 30일 이상 된 감사 로그 삭제: {$deletedLogs}건";

    // 3. 만료된 예외 처리 비활성화
    $stmt = $conn->prepare("UPDATE vulnerability_exceptions SET is_active = 0 WHERE expires_at < NOW() AND is_active = 1");
    $stmt->execute();
    $expiredExceptions = $stmt->affected_rows;
    $stmt->close();
    $results[] = "✅ 만료된 예외 처리 비활성화: {$expiredExceptions}건";

    // 4. 비활성화된 주기적 스캔 중 30일 이상 된 것 삭제
    $stmt = $conn->prepare("DELETE FROM scheduled_scans WHERE is_active = 0 AND updated_at < DATE_SUB(NOW(), INTERVAL 30 DAY)");
    $stmt->execute();
    $deletedSchedules = $stmt->affected_rows;
    $stmt->close();
    $results[] = "✅ 오래된 비활성 스케줄 삭제: {$deletedSchedules}건";

    // 5. demo 계정 확인 및 재생성
    $result = $conn->query("SELECT id FROM users WHERE username = 'demo'");
    if ($result->num_rows === 0) {
        $demoPass = password_hash('demo123', PASSWORD_BCRYPT);
        $stmt = $conn->prepare("INSERT INTO users (username, password_hash, role, email) VALUES ('demo', ?, 'demo', 'demo@interview.local')");
        $stmt->bind_param("s", $demoPass);
        $stmt->execute();
        $stmt->close();
        $results[] = "✅ demo 계정 재생성 완료";
    } else {
        // 비밀번호 초기화
        $demoPass = password_hash('demo123', PASSWORD_BCRYPT);
        $stmt = $conn->prepare("UPDATE users SET password_hash = ?, is_active = 1 WHERE username = 'demo'");
        $stmt->bind_param("s", $demoPass);
        $stmt->execute();
        $stmt->close();
        $results[] = "✅ demo 계정 비밀번호 초기화 완료";
    }

    // 6. admin 계정 확인 및 재생성
    $result = $conn->query("SELECT id FROM users WHERE username = 'admin'");
    if ($result->num_rows === 0) {
        $adminPass = password_hash('admin123', PASSWORD_BCRYPT);
        $stmt = $conn->prepare("INSERT INTO users (username, password_hash, role, email) VALUES ('admin', ?, 'admin', 'admin@localhost')");
        $stmt->bind_param("s", $adminPass);
        $stmt->execute();
        $stmt->close();
        $results[] = "✅ admin 계정 재생성 완료";
    }

    // 7. 설정 오류(misconfig) 테이블 정리
    $stmt = $conn->prepare("DELETE FROM scan_misconfigs WHERE scan_id IN (SELECT id FROM scan_history WHERE scanned_at < DATE_SUB(NOW(), INTERVAL 7 DAY))");
    if ($stmt) {
        $stmt->execute();
        $deletedMisconfigs = $stmt->affected_rows;
        $stmt->close();
        $results[] = "✅ 오래된 설정 오류 기록 삭제: {$deletedMisconfigs}건";
    }

    // 초기화 완료 로그 기록
    $logStmt = $conn->prepare("INSERT INTO audit_logs (username, action, target_type, details, ip_address) VALUES ('system', 'DEMO_RESET', 'system', ?, 'cron')");
    $details = implode("; ", $results);
    $logStmt->bind_param("s", $details);
    $logStmt->execute();
    $logStmt->close();

    echo "=== 초기화 결과 ===\n";
    foreach ($results as $r) {
        echo "$r\n";
    }
    echo "\n=== 데모 환경 초기화 완료 ===\n";

} catch (Exception $e) {
    echo "❌ 오류 발생: " . $e->getMessage() . "\n";
    exit(1);
}

$conn->close();

