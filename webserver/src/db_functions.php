<?php
// MySQL 연결 설정 (재시도 로직 포함)
function getDbConnection($maxRetries = 5, $retryDelay = 3) {
    $host = "mysql";  // Docker 서비스 이름
    $username = "trivy_user";
    $password = "trivy_password";
    $dbname = "trivy_db";

    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

    // 🔄 MySQL 초기화 대기를 위한 재시도 로직
    for ($i = 0; $i < $maxRetries; $i++) {
        try {
            $conn = new mysqli($host, $username, $password, $dbname);
            if (!$conn->connect_error) {
                // Timezone 설정 (PHP와 동기화)
                $conn->query("SET time_zone = '+09:00'");
                return $conn;
            }
        } catch (mysqli_sql_exception $e) {
            // 마지막 시도가 아니면 대기 후 재시도
            if ($i < $maxRetries - 1) {
                error_log("MySQL connection failed (attempt " . ($i + 1) . "/$maxRetries): " . $e->getMessage());
                sleep($retryDelay);
            } else {
                error_log("MySQL connection failed after $maxRetries attempts: " . $e->getMessage());
                return null;
            }
        }
    }
    return null;
}

// 컬럼 존재 여부 확인
function columnExists($conn, $table, $column) {
    $result = $conn->query("SHOW COLUMNS FROM $table LIKE '$column'");
    return $result && $result->num_rows > 0;
}

// 테이블 생성
function initDatabase($conn) {
    // 스캔 기록 테이블
    $conn->query("
        CREATE TABLE IF NOT EXISTS scan_history (
            id INT AUTO_INCREMENT PRIMARY KEY,
            image_name VARCHAR(255) NOT NULL,
            scan_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            total_vulns INT DEFAULT 0,
            critical_count INT DEFAULT 0,
            high_count INT DEFAULT 0,
            medium_count INT DEFAULT 0,
            low_count INT DEFAULT 0,
            scan_source VARCHAR(20) DEFAULT 'manual'
        )
    ");

    // 기존 테이블에 scan_source 컬럼 추가 (없는 경우만)
    if (!columnExists($conn, 'scan_history', 'scan_source')) {
        $conn->query("ALTER TABLE scan_history ADD COLUMN scan_source VARCHAR(20) DEFAULT 'manual'");
    }

    // 취약점 상세 테이블
    $conn->query("
        CREATE TABLE IF NOT EXISTS scan_vulnerabilities (
            id INT AUTO_INCREMENT PRIMARY KEY,
            scan_id INT NOT NULL,
            library VARCHAR(500),
            vulnerability VARCHAR(255),
            severity VARCHAR(50),
            installed_version VARCHAR(500),
            fixed_version VARCHAR(500),
            title TEXT,
            FOREIGN KEY (scan_id) REFERENCES scan_history(id) ON DELETE CASCADE
        )
    ");

    // 컴플라이언스(설정 오류) 테이블
    $conn->query("
        CREATE TABLE IF NOT EXISTS scan_misconfigs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            scan_id INT NOT NULL,
            config_type VARCHAR(100),
            config_id VARCHAR(255),
            title VARCHAR(500),
            description TEXT,
            severity VARCHAR(50),
            resolution TEXT,
            FOREIGN KEY (scan_id) REFERENCES scan_history(id) ON DELETE CASCADE
        )
    ");

    // 취약점 생명주기 추적 테이블 (MTTR 계산용)
    $conn->query("
        CREATE TABLE IF NOT EXISTS vulnerability_lifecycle (
            id INT AUTO_INCREMENT PRIMARY KEY,
            image_name VARCHAR(255) NOT NULL,
            vulnerability_id VARCHAR(255) NOT NULL,
            severity VARCHAR(50),
            first_seen DATETIME NOT NULL,
            fixed_at DATETIME DEFAULT NULL,
            status ENUM('open', 'fixed', 'excepted') DEFAULT 'open',
            INDEX idx_image_vuln (image_name, vulnerability_id),
            INDEX idx_status (status),
            INDEX idx_fixed (fixed_at)
        )
    ");

    // scan_history에 misconfig 카운트 컬럼 추가
    if (!columnExists($conn, 'scan_history', 'misconfig_count')) {
        @$conn->query("ALTER TABLE scan_history ADD COLUMN misconfig_count INT DEFAULT 0");
    }
    if (!columnExists($conn, 'scan_history', 'misconfig_critical')) {
        @$conn->query("ALTER TABLE scan_history ADD COLUMN misconfig_critical INT DEFAULT 0");
    }
    if (!columnExists($conn, 'scan_history', 'misconfig_high')) {
        @$conn->query("ALTER TABLE scan_history ADD COLUMN misconfig_high INT DEFAULT 0");
    }

    // 예외 처리 테이블 (Risk Acceptance)
    $conn->query("
        CREATE TABLE IF NOT EXISTS vulnerability_exceptions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            vulnerability_id VARCHAR(255) NOT NULL,
            image_pattern VARCHAR(255) DEFAULT '*',
            reason TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            created_by VARCHAR(100) DEFAULT 'admin',
            is_active TINYINT(1) DEFAULT 1,
            INDEX idx_vuln_id (vulnerability_id),
            INDEX idx_expires (expires_at),
            INDEX idx_active (is_active)
        )
    ");

    // 기존 테이블 컬럼 크기 수정 (이미 테이블이 있는 경우) - 에러 무시
    @$conn->query("ALTER TABLE scan_vulnerabilities MODIFY library VARCHAR(500)");
    @$conn->query("ALTER TABLE scan_vulnerabilities MODIFY installed_version VARCHAR(500)");
    @$conn->query("ALTER TABLE scan_vulnerabilities MODIFY fixed_version VARCHAR(500)");

    // AI 추천 결과 테이블 (Gemini API)
    $conn->query("
        CREATE TABLE IF NOT EXISTS ai_recommendations (
            id INT AUTO_INCREMENT PRIMARY KEY,
            scan_id INT NOT NULL,
            recommendation_type ENUM('container', 'cve') DEFAULT 'container',
            cve_id VARCHAR(50) DEFAULT NULL,
            recommendation TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scan_history(id) ON DELETE CASCADE,
            INDEX idx_scan_id (scan_id),
            INDEX idx_cve (cve_id)
        )
    ");

    // 사용자 테이블 (RBAC) - demo 역할 포함
    $conn->query("
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            role ENUM('viewer', 'demo', 'operator', 'admin') NOT NULL DEFAULT 'viewer',
            email VARCHAR(100),
            is_active TINYINT(1) DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            last_login DATETIME,
            INDEX idx_username (username),
            INDEX idx_role (role)
        )
    ");

    // 기존 테이블에 demo 역할 추가 (이미 테이블이 있는 경우)
    @$conn->query("ALTER TABLE users MODIFY COLUMN role ENUM('viewer', 'demo', 'operator', 'admin') NOT NULL DEFAULT 'viewer'");

    // 감사 로그 테이블 (Audit Log)
    $conn->query("
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            username VARCHAR(50),
            action VARCHAR(100) NOT NULL,
            target_type VARCHAR(50),
            target_id VARCHAR(255),
            details TEXT,
            ip_address VARCHAR(45),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_user (user_id),
            INDEX idx_action (action),
            INDEX idx_created (created_at)
        )
    ");

    // 기본 admin 계정 생성 (비밀번호: admin123)
    $result = $conn->query("SELECT id FROM users WHERE username = 'admin'");
    if ($result->num_rows === 0) {
        $adminPass = password_hash('admin123', PASSWORD_BCRYPT);
        $stmt = $conn->prepare("INSERT INTO users (username, password_hash, role, email) VALUES ('admin', ?, 'admin', 'admin@localhost')");
        $stmt->bind_param("s", $adminPass);
        $stmt->execute();
        $stmt->close();
    }

    // 면접관용 데모 계정 생성 (비밀번호: demo123)
    $result = $conn->query("SELECT id FROM users WHERE username = 'demo'");
    if ($result->num_rows === 0) {
        $demoPass = password_hash('demo123', PASSWORD_BCRYPT);
        $stmt = $conn->prepare("INSERT INTO users (username, password_hash, role, email) VALUES ('demo', ?, 'demo', 'demo@interview.local')");
        $stmt->bind_param("s", $demoPass);
        $stmt->execute();
        $stmt->close();
    }

    // 권한 설정 테이블 (Role별/User별 메뉴 및 기능 권한)
    $conn->query("
        CREATE TABLE IF NOT EXISTS permissions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            target_type ENUM('role', 'user') NOT NULL,
            target_id VARCHAR(50) NOT NULL,
            permission_key VARCHAR(100) NOT NULL,
            is_allowed TINYINT(1) DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY unique_permission (target_type, target_id, permission_key),
            INDEX idx_target (target_type, target_id)
        )
    ");

    // 기본 Role 권한 설정 (초기값)
    $defaultPermissions = [
        // viewer 권한
        ['role', 'viewer', 'menu_scan_history', 1],
        ['role', 'viewer', 'menu_container_scan', 0],
        ['role', 'viewer', 'menu_exceptions', 0],
        ['role', 'viewer', 'menu_scheduled_scans', 0],
        ['role', 'viewer', 'menu_users', 0],
        ['role', 'viewer', 'menu_audit_logs', 0],
        ['role', 'viewer', 'action_scan', 0],
        ['role', 'viewer', 'action_delete', 0],
        ['role', 'viewer', 'action_export_csv', 1],
        ['role', 'viewer', 'action_ai_analysis', 1],
        ['role', 'viewer', 'action_send_email', 0],
        // operator 권한
        ['role', 'operator', 'menu_scan_history', 1],
        ['role', 'operator', 'menu_container_scan', 1],
        ['role', 'operator', 'menu_exceptions', 1],
        ['role', 'operator', 'menu_scheduled_scans', 0],
        ['role', 'operator', 'menu_users', 0],
        ['role', 'operator', 'menu_audit_logs', 0],
        ['role', 'operator', 'action_scan', 1],
        ['role', 'operator', 'action_delete', 1],
        ['role', 'operator', 'action_export_csv', 1],
        ['role', 'operator', 'action_ai_analysis', 1],
        ['role', 'operator', 'action_send_email', 1],
        // admin 권한 (모두 허용)
        ['role', 'admin', 'menu_scan_history', 1],
        ['role', 'admin', 'menu_container_scan', 1],
        ['role', 'admin', 'menu_exceptions', 1],
        ['role', 'admin', 'menu_scheduled_scans', 1],
        ['role', 'admin', 'menu_users', 1],
        ['role', 'admin', 'menu_audit_logs', 1],
        ['role', 'admin', 'action_scan', 1],
        ['role', 'admin', 'action_delete', 1],
        ['role', 'admin', 'action_export_csv', 1],
        ['role', 'admin', 'action_ai_analysis', 1],
        ['role', 'admin', 'action_send_email', 1],
        // demo 권한 (operator와 유사하지만 실제 작업 제한)
        ['role', 'demo', 'menu_scan_history', 1],
        ['role', 'demo', 'menu_container_scan', 1],
        ['role', 'demo', 'menu_exceptions', 1],
        ['role', 'demo', 'menu_scheduled_scans', 1],
        ['role', 'demo', 'menu_users', 0],
        ['role', 'demo', 'menu_audit_logs', 1],
        ['role', 'demo', 'action_scan', 1],
        ['role', 'demo', 'action_delete', 0],
        ['role', 'demo', 'action_export_csv', 1],
        ['role', 'demo', 'action_ai_analysis', 1],
        ['role', 'demo', 'action_send_email', 0],
    ];

    // 기본 권한이 없으면 추가
    $checkStmt = $conn->prepare("SELECT COUNT(*) as cnt FROM permissions WHERE target_type = 'role'");
    $checkStmt->execute();
    $checkResult = $checkStmt->get_result()->fetch_assoc();
    $checkStmt->close();

    if ($checkResult['cnt'] == 0) {
        $insertStmt = $conn->prepare("INSERT IGNORE INTO permissions (target_type, target_id, permission_key, is_allowed) VALUES (?, ?, ?, ?)");
        foreach ($defaultPermissions as $perm) {
            $insertStmt->bind_param("sssi", $perm[0], $perm[1], $perm[2], $perm[3]);
            $insertStmt->execute();
        }
        $insertStmt->close();
    }

    // 주기적 스캔 설정 테이블
    $conn->query("
        CREATE TABLE IF NOT EXISTS scheduled_scans (
            id INT AUTO_INCREMENT PRIMARY KEY,
            image_name VARCHAR(255) NOT NULL,
            schedule_type ENUM('hourly', 'daily', 'weekly') NOT NULL DEFAULT 'daily',
            schedule_time TIME DEFAULT '02:00:00',
            schedule_day TINYINT DEFAULT 0,
            is_active TINYINT(1) DEFAULT 1,
            last_run DATETIME,
            next_run DATETIME,
            created_by INT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_active (is_active),
            INDEX idx_next_run (next_run)
        )
    ");

    // deleted_at 컬럼 추가 (없는 경우)
    if (!columnExists($conn, 'vulnerability_exceptions', 'deleted_at')) {
        @$conn->query("ALTER TABLE vulnerability_exceptions ADD COLUMN deleted_at DATETIME DEFAULT NULL");
    }
}

// 스캔 결과 저장 (scan_source: 'manual', 'auto', 'bulk', 'scheduled')
function saveScanResult($conn, $imageName, $trivyData, $scanSource = 'manual') {
    $counts = ['CRITICAL' => 0, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0];
    $misconfigCounts = ['CRITICAL' => 0, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0];
    $vulns = [];
    $misconfigs = [];

    if (isset($trivyData['Results'])) {
        foreach ($trivyData['Results'] as $result) {
            // 취약점 수집
            if (isset($result['Vulnerabilities'])) {
                foreach ($result['Vulnerabilities'] as $v) {
                    $sev = $v['Severity'] ?? 'UNKNOWN';
                    if (isset($counts[$sev])) $counts[$sev]++;
                    $vulns[] = $v;
                }
            }
            // 설정 오류 수집 (Misconfigurations)
            if (isset($result['Misconfigurations'])) {
                foreach ($result['Misconfigurations'] as $m) {
                    $sev = $m['Severity'] ?? 'UNKNOWN';
                    if (isset($misconfigCounts[$sev])) $misconfigCounts[$sev]++;
                    $misconfigs[] = $m;
                }
            }
        }
    }

    $total = array_sum($counts);
    $misconfigTotal = array_sum($misconfigCounts);

    // 스캔 기록 저장
    $stmt = $conn->prepare("INSERT INTO scan_history (image_name, total_vulns, critical_count, high_count, medium_count, low_count, scan_source, misconfig_count, misconfig_critical, misconfig_high) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("siiiissiii", $imageName, $total, $counts['CRITICAL'], $counts['HIGH'], $counts['MEDIUM'], $counts['LOW'], $scanSource, $misconfigTotal, $misconfigCounts['CRITICAL'], $misconfigCounts['HIGH']);
    $stmt->execute();
    $scanId = $conn->insert_id;
    $stmt->close();

    // 취약점 저장
    $stmt = $conn->prepare("INSERT INTO scan_vulnerabilities (scan_id, library, vulnerability, severity, installed_version, fixed_version, title) VALUES (?, ?, ?, ?, ?, ?, ?)");
    foreach ($vulns as $v) {
        $lib = $v['PkgName'] ?? '';
        $vulnId = $v['VulnerabilityID'] ?? '';
        $sev = $v['Severity'] ?? '';
        $installed = $v['InstalledVersion'] ?? '';
        $fixed = $v['FixedVersion'] ?? '';
        $title = $v['Title'] ?? '';
        $stmt->bind_param("issssss", $scanId, $lib, $vulnId, $sev, $installed, $fixed, $title);
        $stmt->execute();
    }
    $stmt->close();

    // 설정 오류 저장
    if (!empty($misconfigs)) {
        $stmt = $conn->prepare("INSERT INTO scan_misconfigs (scan_id, config_type, config_id, title, description, severity, resolution) VALUES (?, ?, ?, ?, ?, ?, ?)");
        foreach ($misconfigs as $m) {
            $configType = $m['Type'] ?? '';
            $configId = $m['ID'] ?? $m['AVDID'] ?? '';
            $title = $m['Title'] ?? '';
            $desc = $m['Description'] ?? '';
            $sev = $m['Severity'] ?? '';
            $resolution = $m['Resolution'] ?? '';
            $stmt->bind_param("issssss", $scanId, $configType, $configId, $title, $desc, $sev, $resolution);
            $stmt->execute();
        }
        $stmt->close();
    }

    // 취약점 생명주기 추적 (MTTR 계산용)
    updateVulnerabilityLifecycle($conn, $imageName, $vulns);

    return $scanId;
}

// =====================================================
// AI 추천 관련 함수들 (Gemini API)
// =====================================================

// AI 추천 저장
function saveAiRecommendation($conn, $scanId, $type, $recommendation, $cveId = null) {
    $stmt = $conn->prepare("INSERT INTO ai_recommendations (scan_id, recommendation_type, cve_id, recommendation) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("isss", $scanId, $type, $cveId, $recommendation);
    $stmt->execute();
    $id = $conn->insert_id;
    $stmt->close();
    return $id;
}

// 스캔 ID로 AI 추천 조회
function getAiRecommendations($conn, $scanId) {
    $stmt = $conn->prepare("SELECT * FROM ai_recommendations WHERE scan_id = ? ORDER BY created_at DESC");
    $stmt->bind_param("i", $scanId);
    $stmt->execute();
    $result = $stmt->get_result();
    $recommendations = [];
    while ($row = $result->fetch_assoc()) {
        $recommendations[] = $row;
    }
    $stmt->close();
    return $recommendations;
}

// 컨테이너 전체 추천 조회
function getContainerAiRecommendation($conn, $scanId) {
    $stmt = $conn->prepare("SELECT recommendation FROM ai_recommendations WHERE scan_id = ? AND recommendation_type = 'container' LIMIT 1");
    $stmt->bind_param("i", $scanId);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();
    $stmt->close();
    return $row ? $row['recommendation'] : null;
}

// CVE별 추천 조회
function getCveAiRecommendation($conn, $scanId, $cveId) {
    $stmt = $conn->prepare("SELECT recommendation FROM ai_recommendations WHERE scan_id = ? AND cve_id = ? LIMIT 1");
    $stmt->bind_param("is", $scanId, $cveId);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();
    $stmt->close();
    return $row ? $row['recommendation'] : null;
}

// 취약점 생명주기 업데이트 (MTTR 계산용)
function updateVulnerabilityLifecycle($conn, $imageName, $currentVulns) {
    $now = date('Y-m-d H:i:s');
    $currentVulnIds = [];

    // 현재 발견된 취약점 ID 목록
    foreach ($currentVulns as $v) {
        $vulnId = $v['VulnerabilityID'] ?? '';
        if (!empty($vulnId)) {
            $currentVulnIds[$vulnId] = $v['Severity'] ?? 'UNKNOWN';
        }
    }

    // 기존 open 취약점 조회
    $stmt = $conn->prepare("SELECT vulnerability_id FROM vulnerability_lifecycle WHERE image_name = ? AND status = 'open'");
    $stmt->bind_param("s", $imageName);
    $stmt->execute();
    $result = $stmt->get_result();
    $existingOpen = [];
    while ($row = $result->fetch_assoc()) {
        $existingOpen[] = $row['vulnerability_id'];
    }
    $stmt->close();

    // 새로 발견된 취약점 등록
    foreach ($currentVulnIds as $vulnId => $severity) {
        if (!in_array($vulnId, $existingOpen)) {
            // 이전에 fixed 됐다가 다시 나타난 경우 확인
            $stmt = $conn->prepare("SELECT id FROM vulnerability_lifecycle WHERE image_name = ? AND vulnerability_id = ? AND status = 'fixed'");
            $stmt->bind_param("ss", $imageName, $vulnId);
            $stmt->execute();
            $existing = $stmt->get_result()->fetch_assoc();
            $stmt->close();

            if ($existing) {
                // 재발 - status를 다시 open으로
                $stmt = $conn->prepare("UPDATE vulnerability_lifecycle SET status = 'open', fixed_at = NULL WHERE id = ?");
                $stmt->bind_param("i", $existing['id']);
                $stmt->execute();
                $stmt->close();
            } else {
                // 신규 등록
                $stmt = $conn->prepare("INSERT INTO vulnerability_lifecycle (image_name, vulnerability_id, severity, first_seen, status) VALUES (?, ?, ?, ?, 'open')");
                $stmt->bind_param("ssss", $imageName, $vulnId, $severity, $now);
                $stmt->execute();
                $stmt->close();
            }
        }
    }

    // 조치된 취약점 표시 (이전엔 있었는데 현재 없는 것)
    foreach ($existingOpen as $vulnId) {
        if (!isset($currentVulnIds[$vulnId])) {
            $stmt = $conn->prepare("UPDATE vulnerability_lifecycle SET status = 'fixed', fixed_at = ? WHERE image_name = ? AND vulnerability_id = ? AND status = 'open'");
            $stmt->bind_param("sss", $now, $imageName, $vulnId);
            $stmt->execute();
            $stmt->close();
        }
    }
}

// 스캔 기록 목록 조회 (검색 지원)
function getScanHistory($conn, $search = '', $source = '') {
    try {
        $sql = "SELECT * FROM scan_history WHERE 1=1";
        $params = [];
        $types = '';

        if (!empty($search)) {
            $sql .= " AND image_name LIKE ?";
            $params[] = "%$search%";
            $types .= 's';
        }

        if (!empty($source)) {
            $sql .= " AND scan_source = ?";
            $params[] = $source;
            $types .= 's';
        }

        $sql .= " ORDER BY scan_date DESC LIMIT 100";

        if (!empty($params)) {
            $stmt = $conn->prepare($sql);
            if (!$stmt) return [];
            $stmt->bind_param($types, ...$params);
            $stmt->execute();
            $result = $stmt->get_result();
        } else {
            $result = $conn->query($sql);
        }

        if (!$result) return [];

        $history = [];
        while ($row = $result->fetch_assoc()) {
            $history[] = $row;
        }
        return $history;
    } catch (Exception $e) {
        return [];
    }
}

// 특정 스캔의 취약점 조회
function getScanVulnerabilities($conn, $scanId) {
    $stmt = $conn->prepare("SELECT * FROM scan_vulnerabilities WHERE scan_id = ? ORDER BY FIELD(severity, 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW')");
    $stmt->bind_param("i", $scanId);
    $stmt->execute();
    $result = $stmt->get_result();
    $vulns = [];
    while ($row = $result->fetch_assoc()) {
        $vulns[] = $row;
    }
    $stmt->close();
    return $vulns;
}

// 스캔 삭제
function deleteScan($conn, $scanId) {
    $stmt = $conn->prepare("DELETE FROM scan_history WHERE id = ?");
    $stmt->bind_param("i", $scanId);
    $stmt->execute();
    $stmt->close();
}

// 특정 이미지의 최근 2개 스캔 조회 (diff용)
function getRecentScansForImage($conn, $imageName, $limit = 2) {
    $stmt = $conn->prepare("SELECT * FROM scan_history WHERE image_name = ? ORDER BY scan_date DESC LIMIT ?");
    $stmt->bind_param("si", $imageName, $limit);
    $stmt->execute();
    $result = $stmt->get_result();
    $scans = [];
    while ($row = $result->fetch_assoc()) {
        $scans[] = $row;
    }
    $stmt->close();
    return $scans;
}

// 두 스캔 간의 diff 계산
function calculateScanDiff($conn, $oldScanId, $newScanId) {
    $oldVulns = getScanVulnerabilities($conn, $oldScanId);
    $newVulns = getScanVulnerabilities($conn, $newScanId);

    // vulnerability ID 기준으로 맵 생성
    $oldMap = [];
    foreach ($oldVulns as $v) {
        $oldMap[$v['vulnerability']] = $v;
    }

    $newMap = [];
    foreach ($newVulns as $v) {
        $newMap[$v['vulnerability']] = $v;
    }

    $added = [];   // 새로 추가된 취약점
    $removed = []; // 해결된 취약점
    $unchanged = []; // 그대로인 취약점

    // 새로 추가된 취약점 찾기
    foreach ($newVulns as $v) {
        if (!isset($oldMap[$v['vulnerability']])) {
            $added[] = $v;
        } else {
            $unchanged[] = $v;
        }
    }

    // 해결된 취약점 찾기
    foreach ($oldVulns as $v) {
        if (!isset($newMap[$v['vulnerability']])) {
            $removed[] = $v;
        }
    }

    return [
        'added' => $added,
        'removed' => $removed,
        'unchanged' => $unchanged,
        'summary' => [
            'added_count' => count($added),
            'removed_count' => count($removed),
            'unchanged_count' => count($unchanged)
        ]
    ];
}

// 이미지별 스캔 기록 조회
function getScanHistoryByImage($conn) {
    $result = $conn->query("
        SELECT image_name,
               COUNT(*) as scan_count,
               MAX(scan_date) as last_scan,
               MAX(id) as latest_scan_id
        FROM scan_history
        GROUP BY image_name
        ORDER BY last_scan DESC
    ");
    $images = [];
    while ($row = $result->fetch_assoc()) {
        $images[] = $row;
    }
    return $images;
}

// 특정 이미지의 모든 스캔 기록
function getScansForImage($conn, $imageName) {
    $stmt = $conn->prepare("SELECT * FROM scan_history WHERE image_name = ? ORDER BY scan_date DESC");
    $stmt->bind_param("s", $imageName);
    $stmt->execute();
    $result = $stmt->get_result();
    $scans = [];
    while ($row = $result->fetch_assoc()) {
        $scans[] = $row;
    }
    $stmt->close();
    return $scans;
}

// =====================================================
// 예외 처리 (Risk Acceptance) 함수들
// =====================================================

// 예외 등록
function addException($conn, $vulnId, $imagePattern, $reason, $expiresAt, $createdBy = 'admin') {
    $stmt = $conn->prepare("INSERT INTO vulnerability_exceptions (vulnerability_id, image_pattern, reason, expires_at, created_by) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param("sssss", $vulnId, $imagePattern, $reason, $expiresAt, $createdBy);
    $stmt->execute();
    $id = $conn->insert_id;
    $stmt->close();
    return $id;
}

// 활성 예외 목록 조회
function getActiveExceptions($conn) {
    $result = $conn->query("
        SELECT * FROM vulnerability_exceptions
        WHERE is_active = 1 AND expires_at > NOW()
        ORDER BY created_at DESC
    ");
    $exceptions = [];
    while ($row = $result->fetch_assoc()) {
        $exceptions[] = $row;
    }
    return $exceptions;
}

// 만료된 예외 조회 (재알림용)
function getExpiredExceptions($conn) {
    $result = $conn->query("
        SELECT * FROM vulnerability_exceptions
        WHERE is_active = 1 AND expires_at <= NOW()
        ORDER BY expires_at DESC
    ");
    $exceptions = [];
    while ($row = $result->fetch_assoc()) {
        $exceptions[] = $row;
    }
    return $exceptions;
}

// 특정 취약점이 예외 처리되어 있는지 확인
function isExcepted($conn, $vulnId, $imageName = null) {
    $sql = "SELECT id FROM vulnerability_exceptions WHERE vulnerability_id = ? AND is_active = 1 AND expires_at > NOW()";
    if ($imageName) {
        $sql .= " AND (image_pattern = '*' OR image_pattern = ? OR ? LIKE REPLACE(image_pattern, '*', '%'))";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("sss", $vulnId, $imageName, $imageName);
    } else {
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("s", $vulnId);
    }
    $stmt->execute();
    $result = $stmt->get_result();
    $excepted = $result->num_rows > 0;
    $stmt->close();
    return $excepted;
}

// 예외 삭제 (비활성화)
function deleteException($conn, $exceptionId) {
    $stmt = $conn->prepare("UPDATE vulnerability_exceptions SET is_active = 0 WHERE id = ?");
    $stmt->bind_param("i", $exceptionId);
    $stmt->execute();
    $stmt->close();
}

// 만료된 예외 마킹 및 반환 (배치 처리용)
function processExpiredExceptions($conn) {
    // 만료된 예외 조회
    $expired = getExpiredExceptions($conn);

    // 만료된 예외 비활성화
    if (!empty($expired)) {
        $conn->query("UPDATE vulnerability_exceptions SET is_active = 0 WHERE expires_at <= NOW()");
    }

    return $expired;
}

// 예외 처리된 취약점 제외하고 조회
function getScanVulnerabilitiesFiltered($conn, $scanId, $imageName = null, $includeExcepted = false) {
    $vulns = getScanVulnerabilities($conn, $scanId);

    if ($includeExcepted) {
        // 예외 여부 표시 추가
        foreach ($vulns as &$v) {
            $v['is_excepted'] = isExcepted($conn, $v['vulnerability'], $imageName);
        }
        return $vulns;
    }

    // 예외 처리된 항목 제외
    return array_filter($vulns, function($v) use ($conn, $imageName) {
        return !isExcepted($conn, $v['vulnerability'], $imageName);
    });
}

// 모든 예외 목록 조회 (만료 포함)
function getAllExceptions($conn) {
    $result = $conn->query("
        SELECT *,
            CASE
                WHEN expires_at <= NOW() THEN 'expired'
                WHEN is_active = 0 THEN 'deleted'
                ELSE 'active'
            END as status
        FROM vulnerability_exceptions
        ORDER BY created_at DESC
    ");
    $exceptions = [];
    while ($row = $result->fetch_assoc()) {
        $exceptions[] = $row;
    }
    return $exceptions;
}

// ========================================
// 사용자 인증 및 RBAC 함수
// ========================================

// 로그인 처리
function authenticateUser($conn, $username, $password) {
    $stmt = $conn->prepare("SELECT id, username, password_hash, role, email, is_active FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();
    $stmt->close();

    if (!$user) {
        return ['success' => false, 'error' => '사용자를 찾을 수 없습니다.'];
    }

    if (!$user['is_active']) {
        return ['success' => false, 'error' => '비활성화된 계정입니다.'];
    }

    if (!password_verify($password, $user['password_hash'])) {
        return ['success' => false, 'error' => '비밀번호가 일치하지 않습니다.'];
    }

    // 마지막 로그인 시간 업데이트
    $conn->query("UPDATE users SET last_login = NOW() WHERE id = {$user['id']}");

    unset($user['password_hash']);
    return ['success' => true, 'user' => $user];
}

// 사용자 생성 (Admin만)
function createUser($conn, $username, $password, $role, $email = '') {
    if (!in_array($role, ['viewer', 'operator', 'admin'])) {
        return ['success' => false, 'error' => '유효하지 않은 권한입니다.'];
    }

    $passwordHash = password_hash($password, PASSWORD_BCRYPT);
    $stmt = $conn->prepare("INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("ssss", $username, $passwordHash, $role, $email);

    try {
        $stmt->execute();
        $userId = $conn->insert_id;
        $stmt->close();
        return ['success' => true, 'user_id' => $userId];
    } catch (mysqli_sql_exception $e) {
        $stmt->close();
        if (strpos($e->getMessage(), 'Duplicate') !== false) {
            return ['success' => false, 'error' => '이미 존재하는 사용자명입니다.'];
        }
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

// 사용자 목록 조회
function getUsers($conn) {
    $result = $conn->query("SELECT id, username, role, email, is_active, created_at, last_login FROM users ORDER BY created_at DESC");
    $users = [];
    while ($row = $result->fetch_assoc()) {
        $users[] = $row;
    }
    return $users;
}

// 사용자 정보 조회
function getUserById($conn, $userId) {
    $stmt = $conn->prepare("SELECT id, username, role, email, is_active, created_at, last_login FROM users WHERE id = ?");
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();
    $stmt->close();
    return $user;
}

// 사용자 권한 변경
function updateUserRole($conn, $userId, $newRole) {
    if (!in_array($newRole, ['viewer', 'operator', 'admin'])) {
        return ['success' => false, 'error' => '유효하지 않은 권한입니다.'];
    }
    $stmt = $conn->prepare("UPDATE users SET role = ? WHERE id = ?");
    $stmt->bind_param("si", $newRole, $userId);
    $stmt->execute();
    $stmt->close();
    return ['success' => true];
}

// 사용자 삭제 (비활성화)
function deleteUser($conn, $userId) {
    $stmt = $conn->prepare("UPDATE users SET is_active = 0 WHERE id = ?");
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $stmt->close();
    return ['success' => true];
}

// 비밀번호 변경
function changePassword($conn, $userId, $newPassword) {
    $passwordHash = password_hash($newPassword, PASSWORD_BCRYPT);
    $stmt = $conn->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
    $stmt->bind_param("si", $passwordHash, $userId);
    $stmt->execute();
    $stmt->close();
    return ['success' => true];
}

// ========================================
// 감사 로그 함수
// ========================================

// 감사 로그 기록
function logAudit($conn, $userId, $username, $action, $targetType = null, $targetId = null, $details = null) {
    $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $stmt = $conn->prepare("INSERT INTO audit_logs (user_id, username, action, target_type, target_id, details, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("issssss", $userId, $username, $action, $targetType, $targetId, $details, $ipAddress);
    $stmt->execute();
    $stmt->close();
}

// 감사 로그 조회
function getAuditLogs($conn, $limit = 100, $filters = []) {
    $sql = "SELECT * FROM audit_logs WHERE 1=1";
    $params = [];
    $types = "";

    if (!empty($filters['user_id'])) {
        $sql .= " AND user_id = ?";
        $params[] = $filters['user_id'];
        $types .= "i";
    }
    if (!empty($filters['action'])) {
        $sql .= " AND action = ?";
        $params[] = $filters['action'];
        $types .= "s";
    }
    if (!empty($filters['date_from'])) {
        $sql .= " AND created_at >= ?";
        $params[] = $filters['date_from'];
        $types .= "s";
    }
    if (!empty($filters['date_to'])) {
        $sql .= " AND created_at <= ?";
        $params[] = $filters['date_to'];
        $types .= "s";
    }

    $sql .= " ORDER BY created_at DESC LIMIT ?";
    $params[] = $limit;
    $types .= "i";

    $stmt = $conn->prepare($sql);
    if (!empty($params)) {
        $stmt->bind_param($types, ...$params);
    }
    $stmt->execute();
    $result = $stmt->get_result();
    $logs = [];
    while ($row = $result->fetch_assoc()) {
        $logs[] = $row;
    }
    $stmt->close();
    return $logs;
}

// 권한 체크 헬퍼
function hasPermission($userRole, $requiredLevel) {
    $levels = ['viewer' => 1, 'operator' => 2, 'admin' => 3];
    return ($levels[$userRole] ?? 0) >= ($levels[$requiredLevel] ?? 99);
}

// ========================================
// 주기적 스캔 설정 함수
// ========================================

// 주기적 스캔 추가
function addScheduledScan($conn, $imageName, $scheduleType, $scheduleTime, $scheduleDay, $createdBy) {
    $nextRun = calculateNextRun($scheduleType, $scheduleTime, $scheduleDay);
    $stmt = $conn->prepare("INSERT INTO scheduled_scans (image_name, schedule_type, schedule_time, schedule_day, next_run, created_by) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("sssisi", $imageName, $scheduleType, $scheduleTime, $scheduleDay, $nextRun, $createdBy);
    $stmt->execute();
    $id = $conn->insert_id;
    $stmt->close();
    return $id;
}

// 다음 실행 시간 계산
function calculateNextRun($scheduleType, $scheduleTime, $scheduleDay = 0) {
    $now = new DateTime();
    $time = explode(':', $scheduleTime);
    $hour = (int)($time[0] ?? 2);
    $minute = (int)($time[1] ?? 0);

    switch ($scheduleType) {
        case 'hourly':
            $next = clone $now;
            $next->setTime((int)$now->format('H'), $minute, 0);
            if ($next <= $now) {
                $next->modify('+1 hour');
            }
            break;
        case 'daily':
            $next = clone $now;
            $next->setTime($hour, $minute, 0);
            if ($next <= $now) {
                $next->modify('+1 day');
            }
            break;
        case 'weekly':
            $next = clone $now;
            $next->setTime($hour, $minute, 0);
            $currentDay = (int)$now->format('w'); // 0=Sunday
            $targetDay = $scheduleDay;
            $daysToAdd = ($targetDay - $currentDay + 7) % 7;
            if ($daysToAdd == 0 && $next <= $now) {
                $daysToAdd = 7;
            }
            $next->modify("+{$daysToAdd} days");
            break;
        default:
            $next = clone $now;
            $next->modify('+1 day');
    }
    return $next->format('Y-m-d H:i:s');
}

// 주기적 스캔 목록
function getScheduledScans($conn, $activeOnly = true) {
    $sql = "SELECT s.*, u.username as created_by_name FROM scheduled_scans s LEFT JOIN users u ON s.created_by = u.id";
    if ($activeOnly) {
        $sql .= " WHERE s.is_active = 1";
    }
    $sql .= " ORDER BY s.created_at DESC";
    $result = $conn->query($sql);
    $scans = [];
    while ($row = $result->fetch_assoc()) {
        $scans[] = $row;
    }
    return $scans;
}

// 주기적 스캔 수정
function updateScheduledScan($conn, $id, $imageName, $scheduleType, $scheduleTime, $scheduleDay, $isActive) {
    $nextRun = calculateNextRun($scheduleType, $scheduleTime, $scheduleDay);
    $stmt = $conn->prepare("UPDATE scheduled_scans SET image_name = ?, schedule_type = ?, schedule_time = ?, schedule_day = ?, is_active = ?, next_run = ? WHERE id = ?");
    $stmt->bind_param("sssiisi", $imageName, $scheduleType, $scheduleTime, $scheduleDay, $isActive, $nextRun, $id);
    $stmt->execute();
    $stmt->close();
}

// 주기적 스캔 삭제
function deleteScheduledScan($conn, $id) {
    $stmt = $conn->prepare("DELETE FROM scheduled_scans WHERE id = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $stmt->close();
}

// 실행 대상 스캔 가져오기
function getDueScans($conn) {
    $now = date('Y-m-d H:i:s');
    $stmt = $conn->prepare("SELECT * FROM scheduled_scans WHERE is_active = 1 AND next_run <= ?");
    $stmt->bind_param("s", $now);
    $stmt->execute();
    $result = $stmt->get_result();
    $scans = [];
    while ($row = $result->fetch_assoc()) {
        $scans[] = $row;
    }
    $stmt->close();
    return $scans;
}

// 스캔 완료 후 업데이트
function markScanComplete($conn, $id) {
    // 현재 설정 가져오기
    $stmt = $conn->prepare("SELECT schedule_type, schedule_time, schedule_day FROM scheduled_scans WHERE id = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if ($row) {
        $nextRun = calculateNextRun($row['schedule_type'], $row['schedule_time'], $row['schedule_day']);
        $now = date('Y-m-d H:i:s');
        $stmt = $conn->prepare("UPDATE scheduled_scans SET last_run = ?, next_run = ? WHERE id = ?");
        $stmt->bind_param("ssi", $now, $nextRun, $id);
        $stmt->execute();
        $stmt->close();
    }
}

// ========================================
// 권한 관리 함수 (Permission Management)
// ========================================

/**
 * 권한 키 목록 정의
 */
function getPermissionKeys() {
    return [
        'menu_scan_history' => ['label' => '📋 스캔 기록', 'group' => 'menu'],
        'menu_container_scan' => ['label' => '🔍 컨테이너 스캔', 'group' => 'menu'],
        'menu_exceptions' => ['label' => '🛡️ 예외 관리', 'group' => 'menu'],
        'menu_scheduled_scans' => ['label' => '⏰ 주기적 스캔', 'group' => 'menu'],
        'menu_users' => ['label' => '👥 사용자 관리', 'group' => 'menu'],
        'menu_audit_logs' => ['label' => '📜 감사 로그', 'group' => 'menu'],
        'action_scan' => ['label' => '🔍 스캔 실행', 'group' => 'action'],
        'action_delete' => ['label' => '🗑️ 삭제', 'group' => 'action'],
        'action_export_csv' => ['label' => '📥 CSV 내보내기', 'group' => 'action'],
        'action_ai_analysis' => ['label' => '🤖 AI 분석', 'group' => 'action'],
        'action_send_email' => ['label' => '📧 이메일 발송', 'group' => 'action'],
    ];
}

/**
 * Role별 권한 조회
 */
function getRolePermissions($conn, $role) {
    $stmt = $conn->prepare("SELECT permission_key, is_allowed FROM permissions WHERE target_type = 'role' AND target_id = ?");
    $stmt->bind_param("s", $role);
    $stmt->execute();
    $result = $stmt->get_result();
    $permissions = [];
    while ($row = $result->fetch_assoc()) {
        $permissions[$row['permission_key']] = (bool)$row['is_allowed'];
    }
    $stmt->close();
    return $permissions;
}

/**
 * User별 권한 조회 (Role 권한 + User 오버라이드)
 */
function getUserPermissions($conn, $userId, $userRole) {
    // 기본 Role 권한
    $permissions = getRolePermissions($conn, $userRole);

    // User별 오버라이드
    $stmt = $conn->prepare("SELECT permission_key, is_allowed FROM permissions WHERE target_type = 'user' AND target_id = ?");
    $userIdStr = (string)$userId;
    $stmt->bind_param("s", $userIdStr);
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) {
        $permissions[$row['permission_key']] = (bool)$row['is_allowed'];
    }
    $stmt->close();
    return $permissions;
}

/**
 * Role 권한 업데이트
 */
function updateRolePermission($conn, $role, $permissionKey, $isAllowed) {
    $stmt = $conn->prepare("INSERT INTO permissions (target_type, target_id, permission_key, is_allowed)
                            VALUES ('role', ?, ?, ?)
                            ON DUPLICATE KEY UPDATE is_allowed = VALUES(is_allowed), updated_at = NOW()");
    $stmt->bind_param("ssi", $role, $permissionKey, $isAllowed);
    $stmt->execute();
    $stmt->close();
    return true;
}

/**
 * User별 권한 오버라이드 설정
 */
function updateUserPermission($conn, $userId, $permissionKey, $isAllowed) {
    $userIdStr = (string)$userId;
    $stmt = $conn->prepare("INSERT INTO permissions (target_type, target_id, permission_key, is_allowed)
                            VALUES ('user', ?, ?, ?)
                            ON DUPLICATE KEY UPDATE is_allowed = VALUES(is_allowed), updated_at = NOW()");
    $stmt->bind_param("ssi", $userIdStr, $permissionKey, $isAllowed);
    $stmt->execute();
    $stmt->close();
    return true;
}

/**
 * User별 권한 오버라이드 삭제 (Role 기본값으로 복원)
 */
function resetUserPermission($conn, $userId, $permissionKey = null) {
    $userIdStr = (string)$userId;
    if ($permissionKey) {
        $stmt = $conn->prepare("DELETE FROM permissions WHERE target_type = 'user' AND target_id = ? AND permission_key = ?");
        $stmt->bind_param("ss", $userIdStr, $permissionKey);
    } else {
        $stmt = $conn->prepare("DELETE FROM permissions WHERE target_type = 'user' AND target_id = ?");
        $stmt->bind_param("s", $userIdStr);
    }
    $stmt->execute();
    $stmt->close();
    return true;
}

/**
 * 특정 권한 확인 (세션 사용자 기준)
 */
function checkPermission($conn, $permissionKey) {
    if (!isset($_SESSION['user'])) return false;

    $userId = $_SESSION['user']['id'];
    $userRole = $_SESSION['user']['role'];

    // admin은 모든 권한 허용
    if ($userRole === 'admin') return true;

    $permissions = getUserPermissions($conn, $userId, $userRole);
    return $permissions[$permissionKey] ?? false;
}

/**
 * 모든 Role의 권한 조회
 */
function getAllRolePermissions($conn) {
    $roles = ['viewer', 'demo', 'operator', 'admin'];
    $allPermissions = [];
    foreach ($roles as $role) {
        $allPermissions[$role] = getRolePermissions($conn, $role);
    }
    return $allPermissions;
}

