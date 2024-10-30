<?php
// scan_with_trivy.php
$log_level = $_GET['log_level'] ?? 'INFO'; // 기본값은 INFO

// 명령어 실행
$command = "trivy --severity $log_level --format json --output trivy_report.json my-php-app:latest";
exec($command, $output, $result_code);

if ($result_code === 0) {
    echo "Scan completed successfully. <a href='trivy_report.json'>Download JSON Report</a>";
} else {
    echo "Error during scan. Check log for details.";
}
?>
