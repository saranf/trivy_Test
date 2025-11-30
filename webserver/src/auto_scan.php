<?php
/**
 * Docker 컨테이너 자동 스캔 API
 * - 컨테이너 시작 이벤트 감지 시 호출
 * - 모든 실행 중인 컨테이너 스캔
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

// Trivy 스캔 실행
function runTrivyScan($image, $severity = 'HIGH,CRITICAL') {
    $safeImage = escapeshellarg($image);
    $safeSeverity = escapeshellarg($severity);
    
    $command = "trivy image --no-progress --severity $safeSeverity --format json $safeImage 2>/dev/null";
    exec($command, $output, $result_code);
    
    $jsonOutput = implode("\n", $output);
    return json_decode($jsonOutput, true);
}

// 실행 중인 컨테이너 목록
function getRunningContainers() {
    exec('docker ps --format "{{.Image}}|{{.Names}}"', $output, $result_code);
    $containers = [];
    if ($result_code === 0) {
        foreach ($output as $line) {
            $parts = explode('|', $line);
            if (count($parts) === 2) {
                $containers[] = [
                    'image' => $parts[0],
                    'name' => $parts[1]
                ];
            }
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

// 특정 이미지 스캔 및 저장
if ($action === 'scan_image') {
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
    
    $scanId = saveScanResult($conn, $image, $data);
    $conn->close();
    
    echo json_encode(['success' => true, 'scanId' => $scanId, 'image' => $image]);
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
            $scanId = saveScanResult($conn, $image, $data);
            $results[] = ['image' => $image, 'status' => 'scanned', 'scanId' => $scanId];
            $scannedImages[] = $image;
        } else {
            $results[] = ['image' => $image, 'status' => 'failed'];
        }
    }
    
    $conn->close();
    echo json_encode(['success' => true, 'results' => $results]);
    exit;
}

// 상태 확인
echo json_encode([
    'status' => 'ok',
    'endpoints' => [
        'scan_image' => '?action=scan_image&image=IMAGE_NAME',
        'scan_all' => '?action=scan_all&skip_recent=1'
    ]
]);

