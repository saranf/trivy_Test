<?php
// download_csv.php
$host = "localhost";
$username = "trivy_user";
$password = "trivy_password";
$dbname = "trivy_db";

// MySQL 연결
$conn = new mysqli($host, $username, $password, $dbname);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// HTTP 헤더 설정 (CSV 파일 다운로드)
header('Content-Type: text/csv; charset=utf-8');
header('Content-Disposition: attachment; filename=trivy_report.csv');

// CSV 파일에 작성할 출력 스트림 열기
$output = fopen('php://output', 'w');

// UTF-8 BOM for Excel compatibility
fprintf($output, chr(0xEF).chr(0xBB).chr(0xBF));

// CSV 헤더 작성
fputcsv($output, ['ID', 'Library', 'Vulnerability', 'Severity', 'Installed Version', 'Fixed Version'], ',', '"', '\\');

// 데이터베이스에서 데이터 조회 및 CSV 행 추가
$query = "SELECT * FROM trivy_vulnerabilities";
$result = $conn->query($query);
while ($row = $result->fetch_assoc()) {
    fputcsv($output, $row, ',', '"', '\\');
}

fclose($output);
$conn->close();
exit();
?>
