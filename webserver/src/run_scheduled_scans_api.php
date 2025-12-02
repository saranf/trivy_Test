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

    // 에이전트 API 호출
    $result = scanImageViaAgent($imageName, 'HIGH,CRITICAL', 'vuln,config');

    if (!$result['success']) {
        markScanComplete($conn, $scan['id']);
        $results[] = [
            'image' => $imageName,
            'status' => 'error',
            'message' => 'Agent scan failed: ' . ($result['error'] ?? 'Unknown error')
        ];
        continue;
    }

    $data = $result['result'] ?? null;

    if ($data === null) {
        markScanComplete($conn, $scan['id']);
        $results[] = [
            'image' => $imageName,
            'status' => 'error',
            'message' => 'No data returned from agent'
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

