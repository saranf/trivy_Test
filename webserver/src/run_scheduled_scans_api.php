<?php
/**
 * 주기적 스캔 실행 API (auto_scan 데몬에서 호출)
 */
header('Content-Type: application/json');

require_once 'db_functions.php';

$conn = getDbConnection();
if (!$conn) {
    echo json_encode(['error' => 'Database connection failed']);
    exit(1);
}

initDatabase($conn);

// 실행 대상 스캔 가져오기
$dueScans = getDueScans($conn);

if (empty($dueScans)) {
    echo json_encode(['status' => 'ok', 'message' => 'No scans due', 'count' => 0]);
    exit(0);
}

$results = [];

foreach ($dueScans as $scan) {
    $imageName = $scan['image_name'];
    
    // Trivy 스캔 실행 (v0.29.2 호환)
    $safeTarget = escapeshellarg($imageName);
    $command = "trivy image --security-checks vuln,config --severity HIGH,CRITICAL --format json $safeTarget 2>/dev/null";

    exec($command, $output, $resultCode);

    $jsonOutput = implode("\n", $output);
    $output = []; // 다음 스캔을 위해 초기화

    // JSON 시작 위치 찾기 (INFO 로그가 섞여있을 경우 대비)
    $jsonStart = strpos($jsonOutput, '{');
    if ($jsonStart !== false && $jsonStart > 0) {
        $jsonOutput = substr($jsonOutput, $jsonStart);
    }

    $data = json_decode($jsonOutput, true);

    if ($data === null) {
        // 스캔 실패해도 다음 실행 시간 업데이트
        markScanComplete($conn, $scan['id']);
        $results[] = [
            'image' => $imageName,
            'status' => 'error',
            'message' => 'Failed to parse Trivy output'
        ];
        continue;
    }

    // 스캔 결과 저장
    $scanId = saveScanResult($conn, $imageName, $data, 'scheduled');

    // 스캔 완료 표시 및 다음 실행 시간 계산
    markScanComplete($conn, $scan['id']);
    
    // 감사 로그
    logAudit($conn, null, 'system', 'SCHEDULED_SCAN', 'scan', $scanId, "image: {$imageName}, schedule_id: {$scan['id']}");

    // 취약점 요약
    $stmt = $conn->prepare("SELECT critical_count, high_count, total_vulns FROM scan_history WHERE id = ?");
    $stmt->bind_param("i", $scanId);
    $stmt->execute();
    $summary = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    
    $results[] = [
        'image' => $imageName,
        'status' => 'success',
        'scan_id' => $scanId,
        'total' => $summary['total_vulns'] ?? 0,
        'critical' => $summary['critical_count'] ?? 0,
        'high' => $summary['high_count'] ?? 0
    ];
}

echo json_encode([
    'status' => 'ok',
    'message' => 'Scheduled scans completed',
    'count' => count($results),
    'results' => $results
]);

$conn->close();

