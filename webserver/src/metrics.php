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
    echo "trivy_excepted_vulnerabilities_by_severity{severity=\"low\"} " . $exceptionStats['by_severity']['LOW'] . "\n\n";

    // ========================================
    // MTTR (Mean Time To Remediate) KPI
    // ========================================
    $mttrStats = ['mttr_days' => 0, 'fixed_count' => 0, 'open_count' => 0];

    $tableCheck = $conn->query("SHOW TABLES LIKE 'vulnerability_lifecycle'");
    if ($tableCheck && $tableCheck->num_rows > 0) {
        // MTTR 계산 (fixed 된 취약점의 평균 조치 기간)
        $result = $conn->query("
            SELECT AVG(DATEDIFF(fixed_at, first_seen)) as mttr, COUNT(*) as cnt
            FROM vulnerability_lifecycle
            WHERE status = 'fixed' AND fixed_at IS NOT NULL
        ");
        $mttr = $result->fetch_assoc();
        $mttrStats['mttr_days'] = round($mttr['mttr'] ?? 0, 1);
        $mttrStats['fixed_count'] = $mttr['cnt'] ?? 0;

        // 열린 취약점 수
        $result = $conn->query("SELECT COUNT(*) as cnt FROM vulnerability_lifecycle WHERE status = 'open'");
        $mttrStats['open_count'] = $result->fetch_assoc()['cnt'] ?? 0;
    }

    echo "# HELP trivy_mttr_days Mean Time To Remediate (days)\n";
    echo "# TYPE trivy_mttr_days gauge\n";
    echo "trivy_mttr_days " . $mttrStats['mttr_days'] . "\n\n";

    echo "# HELP trivy_vulnerabilities_fixed Total fixed vulnerabilities\n";
    echo "# TYPE trivy_vulnerabilities_fixed counter\n";
    echo "trivy_vulnerabilities_fixed " . $mttrStats['fixed_count'] . "\n\n";

    echo "# HELP trivy_vulnerabilities_open Currently open vulnerabilities\n";
    echo "# TYPE trivy_vulnerabilities_open gauge\n";
    echo "trivy_vulnerabilities_open " . $mttrStats['open_count'] . "\n\n";

    // ========================================
    // 컴플라이언스 (Misconfigurations) 통계
    // ========================================
    $misconfigStats = ['total' => 0, 'critical' => 0, 'high' => 0];

    $tableCheck = $conn->query("SHOW TABLES LIKE 'scan_misconfigs'");
    if ($tableCheck && $tableCheck->num_rows > 0) {
        // 최신 스캔의 설정 오류 통계
        $result = $conn->query("
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high
            FROM scan_misconfigs sm
            INNER JOIN (
                SELECT id FROM scan_history
                WHERE scan_date = (SELECT MAX(scan_date) FROM scan_history)
            ) latest ON sm.scan_id = latest.id
        ");
        $mc = $result->fetch_assoc();
        $misconfigStats['total'] = $mc['total'] ?? 0;
        $misconfigStats['critical'] = $mc['critical'] ?? 0;
        $misconfigStats['high'] = $mc['high'] ?? 0;
    }

    // scan_history에서 총 설정오류 수
    $result = $conn->query("SELECT SUM(misconfig_count) as total, SUM(misconfig_critical) as critical, SUM(misconfig_high) as high FROM scan_history");
    $mcTotal = $result->fetch_assoc();

    echo "# HELP trivy_misconfigurations_total Total misconfigurations found\n";
    echo "# TYPE trivy_misconfigurations_total gauge\n";
    echo "trivy_misconfigurations_total " . ($mcTotal['total'] ?? 0) . "\n\n";

    echo "# HELP trivy_misconfigurations_by_severity Misconfigurations by severity\n";
    echo "# TYPE trivy_misconfigurations_by_severity gauge\n";
    echo "trivy_misconfigurations_by_severity{severity=\"critical\"} " . ($mcTotal['critical'] ?? 0) . "\n";
    echo "trivy_misconfigurations_by_severity{severity=\"high\"} " . ($mcTotal['high'] ?? 0) . "\n\n";

    // ========================================
    // 에이전트 및 자산 그룹 통계
    // ========================================

    // 에이전트 테이블 확인
    $agentTableCheck = $conn->query("SHOW TABLES LIKE 'agents'");
    if ($agentTableCheck && $agentTableCheck->num_rows > 0) {
        // 에이전트 상태 통계
        $result = $conn->query("SELECT status, COUNT(*) as cnt FROM agents GROUP BY status");
        $agentStats = ['online' => 0, 'offline' => 0, 'error' => 0];
        while ($row = $result->fetch_assoc()) {
            $agentStats[$row['status']] = $row['cnt'];
        }

        echo "# HELP trivy_agents_total Total registered agents by status\n";
        echo "# TYPE trivy_agents_total gauge\n";
        echo "trivy_agents_total{status=\"online\"} " . $agentStats['online'] . "\n";
        echo "trivy_agents_total{status=\"offline\"} " . $agentStats['offline'] . "\n";
        echo "trivy_agents_total{status=\"error\"} " . $agentStats['error'] . "\n\n";

        // 자산 그룹별 취약점 통계
        $groupTableCheck = $conn->query("SHOW TABLES LIKE 'asset_groups'");
        if ($groupTableCheck && $groupTableCheck->num_rows > 0) {
            $result = $conn->query("
                SELECT
                    ag.name as group_name,
                    ag.display_name,
                    COUNT(DISTINCT agm.agent_id) as agent_count,
                    COALESCE(SUM(sh.critical_count), 0) as critical,
                    COALESCE(SUM(sh.high_count), 0) as high,
                    COALESCE(SUM(sh.medium_count), 0) as medium,
                    COALESCE(SUM(sh.low_count), 0) as low
                FROM asset_groups ag
                LEFT JOIN agent_group_mapping agm ON ag.id = agm.group_id
                LEFT JOIN scan_history sh ON agm.agent_id = sh.agent_id
                    AND sh.scan_date > DATE_SUB(NOW(), INTERVAL 24 HOUR)
                GROUP BY ag.id, ag.name, ag.display_name
            ");

            echo "# HELP trivy_asset_group_agents Number of agents per asset group\n";
            echo "# TYPE trivy_asset_group_agents gauge\n";
            while ($row = $result->fetch_assoc()) {
                $groupName = $row['group_name'];
                echo "trivy_asset_group_agents{group=\"{$groupName}\"} " . $row['agent_count'] . "\n";
            }
            echo "\n";

            // 다시 쿼리 실행 (취약점 통계용)
            $result = $conn->query("
                SELECT
                    ag.name as group_name,
                    COALESCE(SUM(sh.critical_count), 0) as critical,
                    COALESCE(SUM(sh.high_count), 0) as high
                FROM asset_groups ag
                LEFT JOIN agent_group_mapping agm ON ag.id = agm.group_id
                LEFT JOIN scan_history sh ON agm.agent_id = sh.agent_id
                    AND sh.scan_date > DATE_SUB(NOW(), INTERVAL 24 HOUR)
                GROUP BY ag.id, ag.name
            ");

            echo "# HELP trivy_asset_group_vulnerabilities Vulnerabilities by asset group (last 24h)\n";
            echo "# TYPE trivy_asset_group_vulnerabilities gauge\n";
            while ($row = $result->fetch_assoc()) {
                $groupName = $row['group_name'];
                echo "trivy_asset_group_vulnerabilities{group=\"{$groupName}\",severity=\"critical\"} " . $row['critical'] . "\n";
                echo "trivy_asset_group_vulnerabilities{group=\"{$groupName}\",severity=\"high\"} " . $row['high'] . "\n";
            }
            echo "\n";
        }

        // 태그별 취약점 통계
        $tagTableCheck = $conn->query("SHOW TABLES LIKE 'asset_tags'");
        if ($tagTableCheck && $tagTableCheck->num_rows > 0) {
            $result = $conn->query("
                SELECT
                    at.name as tag_name,
                    at.category,
                    COUNT(DISTINCT atm.agent_id) as agent_count,
                    COALESCE(SUM(sh.critical_count), 0) as critical,
                    COALESCE(SUM(sh.high_count), 0) as high
                FROM asset_tags at
                LEFT JOIN agent_tag_mapping atm ON at.id = atm.tag_id
                LEFT JOIN scan_history sh ON atm.agent_id = sh.agent_id
                    AND sh.scan_date > DATE_SUB(NOW(), INTERVAL 24 HOUR)
                GROUP BY at.id, at.name, at.category
            ");

            echo "# HELP trivy_asset_tag_vulnerabilities Vulnerabilities by asset tag (last 24h)\n";
            echo "# TYPE trivy_asset_tag_vulnerabilities gauge\n";
            while ($row = $result->fetch_assoc()) {
                $tagName = $row['tag_name'];
                $category = $row['category'];
                echo "trivy_asset_tag_vulnerabilities{tag=\"{$tagName}\",category=\"{$category}\",severity=\"critical\"} " . $row['critical'] . "\n";
                echo "trivy_asset_tag_vulnerabilities{tag=\"{$tagName}\",category=\"{$category}\",severity=\"high\"} " . $row['high'] . "\n";
            }
            echo "\n";
        }
    }

} catch (Exception $e) {
    echo "# Error: " . $e->getMessage() . "\n";
}

