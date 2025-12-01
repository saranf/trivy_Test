<?php
/**
 * Prometheus 메트릭 엔드포인트
 * Trivy 스캔 결과를 Prometheus 형식으로 제공
 */

header('Content-Type: text/plain; charset=utf-8');

require_once 'db_functions.php';

$conn = getDbConnection();
if (!$conn) {
    echo "# Database connection failed\n";
    exit;
}

try {
    initDatabase($conn);
    
    // 전체 스캔 통계
    $result = $conn->query("SELECT COUNT(*) as total_scans FROM scan_history");
    $totalScans = $result->fetch_assoc()['total_scans'] ?? 0;
    
    // 취약점 통계
    $result = $conn->query("
        SELECT 
            SUM(total_vulns) as total_vulns,
            SUM(critical_count) as critical,
            SUM(high_count) as high,
            SUM(medium_count) as medium,
            SUM(low_count) as low
        FROM scan_history
    ");
    $stats = $result->fetch_assoc();
    
    // 최근 24시간 스캔 수
    $result = $conn->query("SELECT COUNT(*) as recent FROM scan_history WHERE scan_date > DATE_SUB(NOW(), INTERVAL 24 HOUR)");
    $recentScans = $result->fetch_assoc()['recent'] ?? 0;
    
    // 스캔 소스별 통계
    $result = $conn->query("SELECT scan_source, COUNT(*) as cnt FROM scan_history GROUP BY scan_source");
    $sourceStats = [];
    while ($row = $result->fetch_assoc()) {
        $sourceStats[$row['scan_source'] ?? 'manual'] = $row['cnt'];
    }
    
    // 이미지별 최신 스캔 취약점 수
    $result = $conn->query("
        SELECT image_name, total_vulns, critical_count, high_count, scan_date
        FROM scan_history h1
        WHERE scan_date = (SELECT MAX(scan_date) FROM scan_history h2 WHERE h2.image_name = h1.image_name)
        ORDER BY scan_date DESC
        LIMIT 20
    ");
    $imageStats = [];
    while ($row = $result->fetch_assoc()) {
        $imageStats[] = $row;
    }

    // 예외 처리 통계
    $exceptionStats = [
        'total' => 0,
        'active' => 0,
        'expired' => 0,
        'by_severity' => ['CRITICAL' => 0, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0]
    ];

    // 테이블 존재 여부 확인
    $tableCheck = $conn->query("SHOW TABLES LIKE 'vulnerability_exceptions'");
    if ($tableCheck && $tableCheck->num_rows > 0) {
        // 전체 예외 수
        $result = $conn->query("SELECT COUNT(*) as cnt FROM vulnerability_exceptions WHERE deleted_at IS NULL");
        $exceptionStats['total'] = $result->fetch_assoc()['cnt'] ?? 0;

        // 활성 예외 수
        $result = $conn->query("SELECT COUNT(*) as cnt FROM vulnerability_exceptions WHERE deleted_at IS NULL AND expires_at > NOW()");
        $exceptionStats['active'] = $result->fetch_assoc()['cnt'] ?? 0;

        // 만료된 예외 수
        $exceptionStats['expired'] = $exceptionStats['total'] - $exceptionStats['active'];

        // 예외 처리된 취약점의 심각도별 카운트 (최신 스캔에서)
        $result = $conn->query("
            SELECT sv.severity, COUNT(DISTINCT sv.vulnerability) as cnt
            FROM scan_vulnerabilities sv
            INNER JOIN vulnerability_exceptions ve ON sv.vulnerability = ve.vulnerability_id
            WHERE ve.deleted_at IS NULL AND ve.expires_at > NOW()
            GROUP BY sv.severity
        ");
        while ($row = $result->fetch_assoc()) {
            $sev = strtoupper($row['severity']);
            if (isset($exceptionStats['by_severity'][$sev])) {
                $exceptionStats['by_severity'][$sev] = (int)$row['cnt'];
            }
        }
    }

    $conn->close();
    
    // Prometheus 형식 출력
    echo "# HELP trivy_total_scans Total number of scans performed\n";
    echo "# TYPE trivy_total_scans counter\n";
    echo "trivy_total_scans $totalScans\n\n";
    
    echo "# HELP trivy_scans_24h Number of scans in last 24 hours\n";
    echo "# TYPE trivy_scans_24h gauge\n";
    echo "trivy_scans_24h $recentScans\n\n";
    
    echo "# HELP trivy_vulnerabilities_total Total vulnerabilities found\n";
    echo "# TYPE trivy_vulnerabilities_total gauge\n";
    echo "trivy_vulnerabilities_total " . ($stats['total_vulns'] ?? 0) . "\n\n";
    
    echo "# HELP trivy_vulnerabilities_by_severity Vulnerabilities by severity\n";
    echo "# TYPE trivy_vulnerabilities_by_severity gauge\n";
    echo "trivy_vulnerabilities_by_severity{severity=\"critical\"} " . ($stats['critical'] ?? 0) . "\n";
    echo "trivy_vulnerabilities_by_severity{severity=\"high\"} " . ($stats['high'] ?? 0) . "\n";
    echo "trivy_vulnerabilities_by_severity{severity=\"medium\"} " . ($stats['medium'] ?? 0) . "\n";
    echo "trivy_vulnerabilities_by_severity{severity=\"low\"} " . ($stats['low'] ?? 0) . "\n\n";
    
    echo "# HELP trivy_scans_by_source Scans by source type\n";
    echo "# TYPE trivy_scans_by_source gauge\n";
    echo "trivy_scans_by_source{source=\"manual\"} " . ($sourceStats['manual'] ?? 0) . "\n";
    echo "trivy_scans_by_source{source=\"auto\"} " . ($sourceStats['auto'] ?? 0) . "\n";
    echo "trivy_scans_by_source{source=\"bulk\"} " . ($sourceStats['bulk'] ?? 0) . "\n\n";
    
    echo "# HELP trivy_image_vulnerabilities Current vulnerabilities per image\n";
    echo "# TYPE trivy_image_vulnerabilities gauge\n";
    foreach ($imageStats as $img) {
        $safeName = preg_replace('/[^a-zA-Z0-9_:]/', '_', $img['image_name']);
        echo "trivy_image_vulnerabilities{image=\"{$img['image_name']}\"} {$img['total_vulns']}\n";
    }
    echo "\n";
    
    echo "# HELP trivy_image_critical Critical vulnerabilities per image\n";
    echo "# TYPE trivy_image_critical gauge\n";
    foreach ($imageStats as $img) {
        echo "trivy_image_critical{image=\"{$img['image_name']}\"} {$img['critical_count']}\n";
    }
    echo "\n";

    // 예외 처리 통계
    echo "# HELP trivy_exceptions_total Total number of vulnerability exceptions\n";
    echo "# TYPE trivy_exceptions_total gauge\n";
    echo "trivy_exceptions_total " . $exceptionStats['total'] . "\n\n";

    echo "# HELP trivy_exceptions_active Currently active exceptions\n";
    echo "# TYPE trivy_exceptions_active gauge\n";
    echo "trivy_exceptions_active " . $exceptionStats['active'] . "\n\n";

    echo "# HELP trivy_exceptions_expired Expired exceptions\n";
    echo "# TYPE trivy_exceptions_expired gauge\n";
    echo "trivy_exceptions_expired " . $exceptionStats['expired'] . "\n\n";

    echo "# HELP trivy_excepted_vulnerabilities_by_severity Excepted vulnerabilities by severity\n";
    echo "# TYPE trivy_excepted_vulnerabilities_by_severity gauge\n";
    echo "trivy_excepted_vulnerabilities_by_severity{severity=\"critical\"} " . $exceptionStats['by_severity']['CRITICAL'] . "\n";
    echo "trivy_excepted_vulnerabilities_by_severity{severity=\"high\"} " . $exceptionStats['by_severity']['HIGH'] . "\n";
    echo "trivy_excepted_vulnerabilities_by_severity{severity=\"medium\"} " . $exceptionStats['by_severity']['MEDIUM'] . "\n";
    echo "trivy_excepted_vulnerabilities_by_severity{severity=\"low\"} " . $exceptionStats['by_severity']['LOW'] . "\n";

} catch (Exception $e) {
    echo "# Error: " . $e->getMessage() . "\n";
}

