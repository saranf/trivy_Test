<?php
/**
 * 주기적 스캔 실행 스크립트 (cron으로 실행)
 * 
 * 사용법: php run_scheduled_scans.php
 * Cron 예시: * * * * * php /var/www/html/run_scheduled_scans.php
 */

// CLI에서만 실행 가능
if (php_sapi_name() !== 'cli') {
    header('Content-Type: application/json');
    echo json_encode(['error' => 'CLI only']);
    exit(1);
}

require_once __DIR__ . '/db_functions.php';

echo "[" . date('Y-m-d H:i:s') . "] Starting scheduled scan check...\n";

$conn = getDbConnection();
if (!$conn) {
    echo "ERROR: Database connection failed\n";
    exit(1);
}

initDatabase($conn);

// 실행 대상 스캔 가져오기
$dueScans = getDueScans($conn);

if (empty($dueScans)) {
    echo "No scans due at this time.\n";
    exit(0);
}

echo "Found " . count($dueScans) . " scan(s) to run.\n";

foreach ($dueScans as $scan) {
    $imageName = $scan['image_name'];
    echo "\n--- Scanning: {$imageName} ---\n";

    // Trivy 스캔 실행
    $safeTarget = escapeshellarg($imageName);
    $command = "trivy image --no-progress --severity HIGH,CRITICAL --format json $safeTarget 2>&1";
    
    echo "Command: {$command}\n";
    exec($command, $output, $resultCode);
    
    $jsonOutput = implode("\n", $output);
    $data = json_decode($jsonOutput, true);

    if ($data === null) {
        echo "ERROR: Failed to parse Trivy output for {$imageName}\n";
        echo "Output: " . substr($jsonOutput, 0, 500) . "\n";
        
        // 다음 실행 시간 업데이트 (실패해도)
        markScanComplete($conn, $scan['id']);
        continue;
    }

    // 스캔 결과 저장
    $scanId = saveScanResult($conn, $imageName, $data, 'scheduled');
    echo "Saved scan result with ID: {$scanId}\n";

    // 스캔 완료 표시 및 다음 실행 시간 계산
    markScanComplete($conn, $scan['id']);
    
    // 감사 로그
    logAudit($conn, null, 'system', 'SCHEDULED_SCAN', 'scan', $scanId, "image: {$imageName}, schedule_id: {$scan['id']}");

    echo "Completed scan for {$imageName}\n";
    
    // 취약점 요약 출력
    $stmt = $conn->prepare("SELECT critical_count, high_count, total_vulns FROM scan_history WHERE id = ?");
    $stmt->bind_param("i", $scanId);
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    
    if ($result) {
        echo "Results: Total={$result['total_vulns']}, Critical={$result['critical_count']}, High={$result['high_count']}\n";
    }
}

echo "\n[" . date('Y-m-d H:i:s') . "] Scheduled scan check completed.\n";
$conn->close();

