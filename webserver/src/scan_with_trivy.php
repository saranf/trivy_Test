<?php
// scan_with_trivy.php - 에이전트 API 사용
require_once 'db_functions.php';

$log_level = $_GET['log_level'] ?? 'HIGH,CRITICAL';
$image = $_GET['image'] ?? 'my-php-app:latest';

// 에이전트 API 호출
$result = scanImageViaAgent($image, $log_level, 'vuln,config');

if ($result['success']) {
    // 결과를 파일로 저장
    file_put_contents('trivy_report.json', json_encode($result['result'], JSON_PRETTY_PRINT));
    echo "Scan completed successfully. <a href='trivy_report.json'>Download JSON Report</a>";
} else {
    echo "Error during scan.<br>";
    echo "Image: " . htmlspecialchars($image) . "<br>";
    echo "Error: " . htmlspecialchars($result['error'] ?? 'Unknown error') . "<br>";
}
?>

