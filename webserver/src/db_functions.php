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

    // ========================================
    // 에이전트 관련 테이블
    // ========================================

    // 에이전트 등록 테이블
    $conn->query("
        CREATE TABLE IF NOT EXISTS agents (
            id INT AUTO_INCREMENT PRIMARY KEY,
            agent_id VARCHAR(64) NOT NULL UNIQUE,
            hostname VARCHAR(255) NOT NULL,
            ip_address VARCHAR(45),
            os_info VARCHAR(255),
            agent_version VARCHAR(20),
            status ENUM('online', 'offline', 'error') DEFAULT 'offline',
            last_heartbeat DATETIME,
            registered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            config JSON,
            tags JSON,
            INDEX idx_agent_id (agent_id),
            INDEX idx_status (status),
            INDEX idx_heartbeat (last_heartbeat)
        )
    ");

    // 에이전트 데이터 테이블 (확장 가능한 구조)
    $conn->query("
        CREATE TABLE IF NOT EXISTS agent_data (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            agent_id VARCHAR(64) NOT NULL,
            data_type VARCHAR(50) NOT NULL,
            data_key VARCHAR(255),
            data_value LONGTEXT,
            collected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            INDEX idx_agent_type (agent_id, data_type),
            INDEX idx_collected (collected_at),
            INDEX idx_type_key (data_type, data_key)
        )
    ");

    // 에이전트 명령 큐 테이블
    $conn->query("
        CREATE TABLE IF NOT EXISTS agent_commands (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            agent_id VARCHAR(64) NOT NULL,
            command_type VARCHAR(50) NOT NULL,
            command_data JSON,
            status ENUM('pending', 'sent', 'completed', 'failed') DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            sent_at DATETIME,
            completed_at DATETIME,
            result TEXT,
            INDEX idx_agent_status (agent_id, status),
            INDEX idx_created (created_at)
        )
    ");

    // scan_history에 agent_id 컬럼 추가
    if (!columnExists($conn, 'scan_history', 'agent_id')) {
        @$conn->query("ALTER TABLE scan_history ADD COLUMN agent_id VARCHAR(64) DEFAULT NULL");
        @$conn->query("ALTER TABLE scan_history ADD INDEX idx_agent (agent_id)");
    }

    // ========================================
    // 자산 관리 테이블
    // ========================================

    // 자산 그룹 테이블
    $conn->query("
        CREATE TABLE IF NOT EXISTS asset_groups (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL UNIQUE,
            display_name VARCHAR(200) NOT NULL,
            description TEXT,
            color VARCHAR(7) DEFAULT '#3498db',
            icon VARCHAR(50) DEFAULT '📁',
            parent_id INT DEFAULT NULL,
            sort_order INT DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_parent (parent_id),
            INDEX idx_name (name)
        )
    ");

    // 자산 태그 테이블
    $conn->query("
        CREATE TABLE IF NOT EXISTS asset_tags (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(50) NOT NULL UNIQUE,
            display_name VARCHAR(100) NOT NULL,
            color VARCHAR(7) DEFAULT '#9b59b6',
            category ENUM('environment', 'team', 'service', 'priority', 'custom') DEFAULT 'custom',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_category (category)
        )
    ");

    // 에이전트-그룹 매핑 테이블
    $conn->query("
        CREATE TABLE IF NOT EXISTS agent_group_mapping (
            agent_id VARCHAR(64) NOT NULL,
            group_id INT NOT NULL,
            assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (agent_id, group_id),
            INDEX idx_group (group_id)
        )
    ");

    // 에이전트-태그 매핑 테이블
    $conn->query("
        CREATE TABLE IF NOT EXISTS agent_tag_mapping (
            agent_id VARCHAR(64) NOT NULL,
            tag_id INT NOT NULL,
            assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (agent_id, tag_id),
            INDEX idx_tag (tag_id)
        )
    ");

    // 기본 자산 그룹 생성
    $conn->query("
        INSERT IGNORE INTO asset_groups (name, display_name, description, color, icon, sort_order) VALUES
        ('production', '🔴 운영', '운영 환경 서버', '#e74c3c', '🔴', 1),
        ('staging', '🟡 스테이징', '스테이징 환경', '#f39c12', '🟡', 2),
        ('development', '🟢 개발', '개발 환경', '#27ae60', '🟢', 3),
        ('testing', '🔵 테스트', '테스트 환경', '#3498db', '🔵', 4)
    ");

    // 기본 태그 생성
    $conn->query("
        INSERT IGNORE INTO asset_tags (name, display_name, color, category) VALUES
        ('prod', 'Production', '#e74c3c', 'environment'),
        ('staging', 'Staging', '#f39c12', 'environment'),
        ('dev', 'Development', '#27ae60', 'environment'),
        ('test', 'Testing', '#3498db', 'environment'),
        ('backend', 'Backend', '#9b59b6', 'team'),
        ('frontend', 'Frontend', '#1abc9c', 'team'),
        ('infra', 'Infrastructure', '#34495e', 'team'),
        ('critical', 'Critical', '#c0392b', 'priority'),
        ('high', 'High', '#e67e22', 'priority'),
        ('normal', 'Normal', '#2980b9', 'priority'),
        ('low', 'Low', '#7f8c8d', 'priority')
    ");
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

    // vulnerability(CVE) + library 조합으로 맵 생성
    // 동일 CVE가 여러 패키지에 존재할 수 있으므로 라이브러리까지 키에 포함한다
    $keyOf = function ($v) {
        return ($v['vulnerability'] ?? '') . '|' . ($v['library'] ?? '');
    };

    $oldMap = [];
    foreach ($oldVulns as $v) {
        $oldMap[$keyOf($v)] = $v;
    }

    $newMap = [];
    foreach ($newVulns as $v) {
        $newMap[$keyOf($v)] = $v;
    }

    $added = [];   // 새로 추가된 취약점
    $removed = []; // 해결된 취약점
    $unchanged = []; // 그대로인 취약점

    // 새로 추가된 취약점 찾기
    foreach ($newVulns as $v) {
        if (!isset($oldMap[$keyOf($v)])) {
            $added[] = $v;
        } else {
            $unchanged[] = $v;
        }
    }

    // 해결된 취약점 찾기
    foreach ($oldVulns as $v) {
        if (!isset($newMap[$keyOf($v)])) {
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

// =====================================================
// Scan Diff V2 — delta 분류 + MORI evidence export
// (CSOP Lab Scope: docs/CSOP_LAB_SCOPE.md)
// =====================================================

// 단일 스캔 메타 조회
function getScanMeta($conn, $scanId) {
    $stmt = $conn->prepare("SELECT * FROM scan_history WHERE id = ?");
    $stmt->bind_param("i", $scanId);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    return $row ?: null;
}

// reopened 판정용: 특정 스캔보다 과거의 같은 이미지 스캔에 존재했던 vulnerability|library 키 집합
function getImageKeysBeforeScan($conn, $imageName, $beforeScanId) {
    $keys = [];
    $stmt = $conn->prepare("
        SELECT DISTINCT sv.vulnerability, sv.library
        FROM scan_vulnerabilities sv
        JOIN scan_history sh ON sv.scan_id = sh.id
        WHERE sh.image_name = ? AND sh.id < ?
    ");
    $stmt->bind_param("si", $imageName, $beforeScanId);
    $stmt->execute();
    $res = $stmt->get_result();
    while ($r = $res->fetch_assoc()) {
        $keys[($r['vulnerability'] ?? '') . '|' . ($r['library'] ?? '')] = true;
    }
    $stmt->close();
    return $keys;
}

// 두 스캔 비교 V2 — 각 finding에 delta_type 부여
// delta_type: new | fixed | unchanged | severity_changed | version_changed | reopened
function calculateScanDiffV2($conn, $oldScanId, $newScanId) {
    $oldVulns = getScanVulnerabilities($conn, $oldScanId);
    $newVulns = getScanVulnerabilities($conn, $newScanId);

    $keyOf = function ($v) {
        return ($v['vulnerability'] ?? '') . '|' . ($v['library'] ?? '');
    };

    $oldMap = [];
    foreach ($oldVulns as $v) { $oldMap[$keyOf($v)] = $v; }
    $newMap = [];
    foreach ($newVulns as $v) { $newMap[$keyOf($v)] = $v; }

    // reopened: old 스캔보다 과거에 존재했던 키 (같은 이미지)
    $oldMeta = getScanMeta($conn, $oldScanId);
    $historyKeys = $oldMeta ? getImageKeysBeforeScan($conn, $oldMeta['image_name'], $oldScanId) : [];

    $rank = ['CRITICAL' => 0, 'HIGH' => 1, 'MEDIUM' => 2, 'LOW' => 3, 'UNKNOWN' => 4];
    $counts = ['new' => 0, 'fixed' => 0, 'unchanged' => 0,
               'severity_changed' => 0, 'version_changed' => 0, 'reopened' => 0];
    $findings = [];

    $mk = function ($v, $delta, $prev) {
        return [
            'vulnerability' => $v['vulnerability'] ?? '',
            'library'       => $v['library'] ?? '',
            'severity'      => strtoupper($v['severity'] ?? 'UNKNOWN'),
            'prev_severity' => $prev ? strtoupper($prev['severity'] ?? 'UNKNOWN') : null,
            'installed_version' => $v['installed_version'] ?? '',
            'fixed_version' => $v['fixed_version'] ?? '',
            'title'         => $v['title'] ?? '',
            'delta_type'    => $delta,
        ];
    };

    // 현재 스캔 기준: new / reopened / unchanged / severity_changed / version_changed
    foreach ($newVulns as $v) {
        $k = $keyOf($v);
        if (!isset($oldMap[$k])) {
            $delta = isset($historyKeys[$k]) ? 'reopened' : 'new';
            $findings[] = $mk($v, $delta, null);
        } else {
            $o = $oldMap[$k];
            if (strtoupper($o['severity'] ?? '') !== strtoupper($v['severity'] ?? '')) {
                $delta = 'severity_changed';
            } elseif (($o['installed_version'] ?? '') !== ($v['installed_version'] ?? '')
                   || ($o['fixed_version'] ?? '') !== ($v['fixed_version'] ?? '')) {
                $delta = 'version_changed';
            } else {
                $delta = 'unchanged';
            }
            $findings[] = $mk($v, $delta, $o);
        }
        $counts[$delta]++;
    }

    // 이전 스캔에만 있던 것 = fixed
    foreach ($oldVulns as $v) {
        if (!isset($newMap[$keyOf($v)])) {
            $findings[] = $mk($v, 'fixed', null);
            $counts['fixed']++;
        }
    }

    // 결정론적 정렬: delta_type, severity, key
    $deltaOrder = ['new' => 0, 'reopened' => 1, 'severity_changed' => 2,
                   'version_changed' => 3, 'unchanged' => 4, 'fixed' => 5];
    usort($findings, function ($a, $b) use ($deltaOrder, $rank) {
        $d = ($deltaOrder[$a['delta_type']] ?? 9) <=> ($deltaOrder[$b['delta_type']] ?? 9);
        if ($d !== 0) return $d;
        $s = ($rank[$a['severity']] ?? 9) <=> ($rank[$b['severity']] ?? 9);
        if ($s !== 0) return $s;
        return strcmp($a['vulnerability'] . $a['library'], $b['vulnerability'] . $b['library']);
    });

    // 현재 스캔의 심각도 요약
    $sev = ['CRITICAL' => 0, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0, 'UNKNOWN' => 0];
    foreach ($newVulns as $v) {
        $s = strtoupper($v['severity'] ?? 'UNKNOWN');
        $sev[$s] = ($sev[$s] ?? 0) + 1;
    }

    return [
        'old_scan_id' => (int)$oldScanId,
        'new_scan_id' => (int)$newScanId,
        'image_name'  => $oldMeta['image_name'] ?? ($newMap ? '' : ''),
        'findings'    => $findings,
        'counts'      => $counts,
        'severity'    => $sev,
        'total_current' => count($newVulns),
    ];
}

// MORI import envelope 생성 (schema: mori.trivy.findings.v1)
function buildMoriEvidenceEnvelope($conn, $oldScanId, $newScanId) {
    $diff = calculateScanDiffV2($conn, $oldScanId, $newScanId);
    $newMeta = getScanMeta($conn, $newScanId);

    $findings = [];
    foreach ($diff['findings'] as $f) {
        $findings[] = [
            'vulnerability_id'  => $f['vulnerability'],
            'package_name'      => $f['library'],
            'installed_version' => $f['installed_version'],
            'fixed_version'     => $f['fixed_version'],
            'severity'          => $f['severity'],
            'delta_type'        => $f['delta_type'],
        ];
    }

    $c = $diff['counts'];
    return [
        'schema_version' => 'mori.trivy.findings.v1',
        'source'         => 'trivy-agent',
        'agent_id'       => $newMeta['agent_id'] ?? null,
        'hostname'       => $newMeta['agent_id'] ?? null,
        'scan_run_id'    => 'scan-' . (int)$newScanId,
        'target'         => $diff['image_name'] ?: ($newMeta['image_name'] ?? ''),
        'generated_at'   => date('c'),
        'summary'        => [
            'new'              => $c['new'],
            'fixed'            => $c['fixed'],
            'unchanged'        => $c['unchanged'],
            'severity_changed' => $c['severity_changed'],
            'version_changed'  => $c['version_changed'],
            'reopened'         => $c['reopened'],
            'critical'         => $diff['severity']['CRITICAL'],
            'high'             => $diff['severity']['HIGH'],
        ],
        'findings' => $findings,
    ];
}

// Diff evidence CSV 생성
function buildScanDiffCsv($conn, $oldScanId, $newScanId) {
    $diff = calculateScanDiffV2($conn, $oldScanId, $newScanId);
    $image = $diff['image_name'];
    $now = date('c');

    $out = fopen('php://temp', 'r+');
    fputcsv($out, ['image', 'package', 'cve', 'delta_type',
                   'previous_severity', 'current_severity',
                   'installed_version', 'fixed_version', 'evidence_time'], ',', '"', '\\');
    foreach ($diff['findings'] as $f) {
        fputcsv($out, [
            $image,
            $f['library'],
            $f['vulnerability'],
            $f['delta_type'],
            $f['prev_severity'] ?? '',
            $f['severity'],
            $f['installed_version'],
            $f['fixed_version'],
            $now,
        ], ',', '"', '\\');
    }
    rewind($out);
    $csv = stream_get_contents($out);
    fclose($out);
    return $csv;
}

// =====================================================
// Finding Lifecycle — CVE 상태 관리 (CSOP Lab sandbox)
// states: open, reviewing, mitigated, accepted_risk, false_positive, fixed, reopened
// (docs/CSOP_LAB_SCOPE.md — MORI Risk Register로 이관 예정 모델)
// =====================================================

function FINDING_LIFECYCLE_STATES() {
    return ['open', 'reviewing', 'mitigated', 'accepted_risk', 'false_positive', 'fixed', 'reopened'];
}

function ensureFindingLifecycleTable($conn) {
    $conn->query("
        CREATE TABLE IF NOT EXISTS finding_lifecycle (
            id INT AUTO_INCREMENT PRIMARY KEY,
            image_name VARCHAR(255) NOT NULL,
            vulnerability_id VARCHAR(255) NOT NULL,
            package_name VARCHAR(500) NOT NULL,
            state VARCHAR(32) NOT NULL DEFAULT 'open',
            risk_decision VARCHAR(20) DEFAULT NULL,
            owner VARCHAR(128) DEFAULT NULL,
            decision_reason TEXT,
            due_date DATE DEFAULT NULL,
            review_date DATE DEFAULT NULL,
            evidence_note TEXT,
            updated_by VARCHAR(128) DEFAULT NULL,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_finding (image_name(191), vulnerability_id(120), package_name(191))
        )
    ");
}

// 이미지의 lifecycle 상태 맵 (key: vulnerability|package)
function getFindingLifecycle($conn, $imageName) {
    ensureFindingLifecycleTable($conn);
    $map = [];
    $stmt = $conn->prepare("SELECT * FROM finding_lifecycle WHERE image_name = ?");
    $stmt->bind_param("s", $imageName);
    $stmt->execute();
    $res = $stmt->get_result();
    while ($r = $res->fetch_assoc()) {
        $map[$r['vulnerability_id'] . '|' . $r['package_name']] = $r;
    }
    $stmt->close();
    return $map;
}

// lifecycle 상태 upsert. 유효하지 않은 state면 false.
function upsertFindingLifecycle($conn, $d, $updatedBy = 'admin') {
    ensureFindingLifecycleTable($conn);
    $state = $d['state'] ?? 'open';
    if (!in_array($state, FINDING_LIFECYCLE_STATES(), true)) {
        return false;
    }
    $image = $d['image_name'] ?? '';
    $vuln  = $d['vulnerability_id'] ?? '';
    $pkg   = $d['package_name'] ?? '';
    if ($image === '' || $vuln === '' || $pkg === '') {
        return false;
    }
    $decision = $d['risk_decision'] ?? null;
    $owner    = $d['owner'] ?? null;
    $reason   = $d['decision_reason'] ?? null;
    $due      = !empty($d['due_date']) ? $d['due_date'] : null;
    $review   = !empty($d['review_date']) ? $d['review_date'] : null;
    $note     = $d['evidence_note'] ?? null;

    $stmt = $conn->prepare("
        INSERT INTO finding_lifecycle
            (image_name, vulnerability_id, package_name, state, risk_decision,
             owner, decision_reason, due_date, review_date, evidence_note, updated_by, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
        ON DUPLICATE KEY UPDATE
            state=VALUES(state), risk_decision=VALUES(risk_decision), owner=VALUES(owner),
            decision_reason=VALUES(decision_reason), due_date=VALUES(due_date),
            review_date=VALUES(review_date), evidence_note=VALUES(evidence_note),
            updated_by=VALUES(updated_by), updated_at=NOW()
    ");
    $stmt->bind_param("sssssssssss", $image, $vuln, $pkg, $state, $decision,
                      $owner, $reason, $due, $review, $note, $updatedBy);
    $ok = $stmt->execute();
    $stmt->close();
    return $ok;
}

// 이미지별 상태 카운트
function getFindingLifecycleCounts($conn, $imageName) {
    ensureFindingLifecycleTable($conn);
    $counts = array_fill_keys(FINDING_LIFECYCLE_STATES(), 0);
    $stmt = $conn->prepare("SELECT state, COUNT(*) c FROM finding_lifecycle WHERE image_name = ? GROUP BY state");
    $stmt->bind_param("s", $imageName);
    $stmt->execute();
    $res = $stmt->get_result();
    while ($r = $res->fetch_assoc()) {
        $counts[$r['state']] = (int)$r['c'];
    }
    $stmt->close();
    return $counts;
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

// 권한 레벨 체크 헬퍼 (Role 레벨 비교용)
function hasRoleLevel($userRole, $requiredLevel) {
    $levels = ['viewer' => 1, 'demo' => 2, 'operator' => 2, 'admin' => 3];
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
        'menu_agents' => ['label' => '🤖 에이전트 관리', 'group' => 'menu'],
        'menu_users' => ['label' => '👥 사용자 관리', 'group' => 'menu'],
        'menu_audit_logs' => ['label' => '📜 감사 로그', 'group' => 'menu'],
        'action_scan' => ['label' => '🔍 스캔 실행', 'group' => 'action'],
        'action_delete' => ['label' => '🗑️ 삭제', 'group' => 'action'],
        'action_export_csv' => ['label' => '📥 CSV 내보내기', 'group' => 'action'],
        'action_ai_analysis' => ['label' => '🤖 AI 분석', 'group' => 'action'],
        'action_send_email' => ['label' => '📧 이메일 발송', 'group' => 'action'],
        'action_agent_command' => ['label' => '🤖 에이전트 명령', 'group' => 'action'],
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

// ========================================
// 에이전트 관리 함수
// ========================================

/**
 * 에이전트 등록/업데이트
 */
function registerAgent($conn, $agentId, $hostname, $ipAddress, $osInfo, $version, $config = null, $tags = null) {
    $stmt = $conn->prepare("
        INSERT INTO agents (agent_id, hostname, ip_address, os_info, agent_version, status, last_heartbeat, config, tags)
        VALUES (?, ?, ?, ?, ?, 'online', NOW(), ?, ?)
        ON DUPLICATE KEY UPDATE
            hostname = VALUES(hostname),
            ip_address = VALUES(ip_address),
            os_info = VALUES(os_info),
            agent_version = VALUES(agent_version),
            status = 'online',
            last_heartbeat = NOW(),
            config = COALESCE(VALUES(config), config),
            tags = COALESCE(VALUES(tags), tags)
    ");
    $configJson = $config ? json_encode($config) : null;
    $tagsJson = $tags ? json_encode($tags) : null;
    $stmt->bind_param("sssssss", $agentId, $hostname, $ipAddress, $osInfo, $version, $configJson, $tagsJson);
    $result = $stmt->execute();
    $stmt->close();
    return $result;
}

/**
 * 에이전트 하트비트 업데이트
 */
function updateAgentHeartbeat($conn, $agentId) {
    $stmt = $conn->prepare("UPDATE agents SET status = 'online', last_heartbeat = NOW() WHERE agent_id = ?");
    $stmt->bind_param("s", $agentId);
    $result = $stmt->execute();
    $stmt->close();
    return $result;
}

/**
 * 에이전트 목록 조회
 */
function getAgents($conn, $status = null) {
    $sql = "SELECT *,
            TIMESTAMPDIFF(SECOND, last_heartbeat, NOW()) as seconds_since_heartbeat
            FROM agents";
    if ($status) {
        $sql .= " WHERE status = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("s", $status);
    } else {
        $sql .= " ORDER BY last_heartbeat DESC";
        $stmt = $conn->prepare($sql);
    }
    $stmt->execute();
    $result = $stmt->get_result();
    $agents = $result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
    return $agents;
}

/**
 * 에이전트 상세 조회
 */
function getAgent($conn, $agentId) {
    $stmt = $conn->prepare("SELECT * FROM agents WHERE agent_id = ?");
    $stmt->bind_param("s", $agentId);
    $stmt->execute();
    $result = $stmt->get_result();
    $agent = $result->fetch_assoc();
    $stmt->close();
    return $agent;
}

/**
 * 에이전트 데이터 저장 (확장 가능한 구조)
 */
function saveAgentData($conn, $agentId, $dataType, $dataKey, $dataValue, $expiresAt = null) {
    $stmt = $conn->prepare("
        INSERT INTO agent_data (agent_id, data_type, data_key, data_value, expires_at)
        VALUES (?, ?, ?, ?, ?)
    ");
    $valueJson = is_array($dataValue) || is_object($dataValue) ? json_encode($dataValue) : $dataValue;
    $stmt->bind_param("sssss", $agentId, $dataType, $dataKey, $valueJson, $expiresAt);
    $result = $stmt->execute();
    $insertId = $conn->insert_id;
    $stmt->close();
    return $result ? $insertId : false;
}

/**
 * 에이전트 데이터 조회
 */
function getAgentData($conn, $agentId, $dataType = null, $limit = 100) {
    $sql = "SELECT * FROM agent_data WHERE agent_id = ?";
    $params = [$agentId];
    $types = "s";

    if ($dataType) {
        $sql .= " AND data_type = ?";
        $params[] = $dataType;
        $types .= "s";
    }

    $sql .= " ORDER BY collected_at DESC LIMIT ?";
    $params[] = $limit;
    $types .= "i";

    $stmt = $conn->prepare($sql);
    $stmt->bind_param($types, ...$params);
    $stmt->execute();
    $result = $stmt->get_result();
    $data = $result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
    return $data;
}

/**
 * 에이전트 명령 추가
 */
function addAgentCommand($conn, $agentId, $commandType, $commandData = null) {
    $stmt = $conn->prepare("
        INSERT INTO agent_commands (agent_id, command_type, command_data)
        VALUES (?, ?, ?)
    ");
    $dataJson = $commandData ? json_encode($commandData) : null;
    $stmt->bind_param("sss", $agentId, $commandType, $dataJson);
    $result = $stmt->execute();
    $insertId = $conn->insert_id;
    $stmt->close();
    return $result ? $insertId : false;
}

/**
 * 대기 중인 명령 조회 (에이전트용)
 */
function getPendingCommands($conn, $agentId) {
    $stmt = $conn->prepare("
        SELECT * FROM agent_commands
        WHERE agent_id = ? AND status = 'pending'
        ORDER BY created_at ASC
    ");
    $stmt->bind_param("s", $agentId);
    $stmt->execute();
    $result = $stmt->get_result();
    $commands = $result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();

    // 명령 상태를 'sent'로 업데이트
    if (!empty($commands)) {
        $ids = array_column($commands, 'id');
        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $stmt = $conn->prepare("UPDATE agent_commands SET status = 'sent', sent_at = NOW() WHERE id IN ($placeholders)");
        $types = str_repeat('i', count($ids));
        $stmt->bind_param($types, ...$ids);
        $stmt->execute();
        $stmt->close();
    }

    return $commands;
}

/**
 * 명령 결과 업데이트
 */
function updateCommandResult($conn, $commandId, $status, $result = null) {
    $stmt = $conn->prepare("
        UPDATE agent_commands
        SET status = ?, completed_at = NOW(), result = ?
        WHERE id = ?
    ");
    $stmt->bind_param("ssi", $status, $result, $commandId);
    $res = $stmt->execute();
    $stmt->close();
    return $res;
}

/**
 * 오래된 에이전트 오프라인 처리 (5분 이상 하트비트 없음)
 */
function markOfflineAgents($conn, $timeoutSeconds = 300) {
    $stmt = $conn->prepare("
        UPDATE agents
        SET status = 'offline'
        WHERE status = 'online'
        AND last_heartbeat < DATE_SUB(NOW(), INTERVAL ? SECOND)
    ");
    $stmt->bind_param("i", $timeoutSeconds);
    $stmt->execute();
    $affected = $stmt->affected_rows;
    $stmt->close();
    return $affected;
}

/**
 * 스캔 결과 저장 (에이전트용 확장)
 */
function saveScanResultFromAgent($conn, $agentId, $imageName, $trivyData, $scanSource = 'agent') {
    // 기존 saveScanResult 호출
    $scanId = saveScanResult($conn, $imageName, $trivyData, $scanSource);

    // agent_id 업데이트
    if ($scanId && $agentId) {
        $stmt = $conn->prepare("UPDATE scan_history SET agent_id = ? WHERE id = ?");
        $stmt->bind_param("si", $agentId, $scanId);
        $stmt->execute();
        $stmt->close();
    }

    return $scanId;
}

/**
 * 에이전트별 스캔 기록 조회
 */
function getScanHistoryByAgent($conn, $agentId = null, $limit = 50) {
    $sql = "SELECT sh.*, a.hostname as agent_hostname
            FROM scan_history sh
            LEFT JOIN agents a ON sh.agent_id = a.agent_id";

    if ($agentId) {
        $sql .= " WHERE sh.agent_id = ?";
        $sql .= " ORDER BY sh.scan_date DESC LIMIT ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("si", $agentId, $limit);
    } else {
        $sql .= " ORDER BY sh.scan_date DESC LIMIT ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $limit);
    }

    $stmt->execute();
    $result = $stmt->get_result();
    $history = $result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
    return $history;
}

// ========================================
// 자산 관리 함수
// ========================================

/**
 * 자산 그룹 목록 조회
 */
function getAssetGroups($conn, $parentId = null) {
    if ($parentId === null) {
        $stmt = $conn->prepare("SELECT * FROM asset_groups WHERE parent_id IS NULL ORDER BY sort_order, name");
        $stmt->execute();
    } else {
        $stmt = $conn->prepare("SELECT * FROM asset_groups WHERE parent_id = ? ORDER BY sort_order, name");
        $stmt->bind_param("i", $parentId);
        $stmt->execute();
    }
    $result = $stmt->get_result();
    $groups = $result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
    return $groups;
}

/**
 * 자산 그룹 생성
 */
function createAssetGroup($conn, $name, $displayName, $description = '', $color = '#3498db', $icon = '📁', $parentId = null) {
    $stmt = $conn->prepare("INSERT INTO asset_groups (name, display_name, description, color, icon, parent_id) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("sssssi", $name, $displayName, $description, $color, $icon, $parentId);
    $result = $stmt->execute();
    $id = $stmt->insert_id;
    $stmt->close();
    return $result ? $id : false;
}

/**
 * 자산 태그 목록 조회
 */
function getAssetTags($conn, $category = null) {
    if ($category === null) {
        $stmt = $conn->prepare("SELECT * FROM asset_tags ORDER BY category, name");
        $stmt->execute();
    } else {
        $stmt = $conn->prepare("SELECT * FROM asset_tags WHERE category = ? ORDER BY name");
        $stmt->bind_param("s", $category);
        $stmt->execute();
    }
    $result = $stmt->get_result();
    $tags = $result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
    return $tags;
}

/**
 * 자산 태그 생성
 */
function createAssetTag($conn, $name, $displayName, $color = '#9b59b6', $category = 'custom') {
    $stmt = $conn->prepare("INSERT INTO asset_tags (name, display_name, color, category) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("ssss", $name, $displayName, $color, $category);
    $result = $stmt->execute();
    $id = $stmt->insert_id;
    $stmt->close();
    return $result ? $id : false;
}

/**
 * 에이전트에 그룹 할당
 */
function assignAgentToGroup($conn, $agentId, $groupId) {
    $stmt = $conn->prepare("INSERT IGNORE INTO agent_group_mapping (agent_id, group_id) VALUES (?, ?)");
    $stmt->bind_param("si", $agentId, $groupId);
    $result = $stmt->execute();
    $stmt->close();
    return $result;
}

/**
 * 에이전트에서 그룹 제거
 */
function removeAgentFromGroup($conn, $agentId, $groupId = null) {
    if ($groupId === null) {
        $stmt = $conn->prepare("DELETE FROM agent_group_mapping WHERE agent_id = ?");
        $stmt->bind_param("s", $agentId);
    } else {
        $stmt = $conn->prepare("DELETE FROM agent_group_mapping WHERE agent_id = ? AND group_id = ?");
        $stmt->bind_param("si", $agentId, $groupId);
    }
    $result = $stmt->execute();
    $stmt->close();
    return $result;
}

/**
 * 에이전트에 태그 할당
 */
function assignAgentTag($conn, $agentId, $tagId) {
    $stmt = $conn->prepare("INSERT IGNORE INTO agent_tag_mapping (agent_id, tag_id) VALUES (?, ?)");
    $stmt->bind_param("si", $agentId, $tagId);
    $result = $stmt->execute();
    $stmt->close();
    return $result;
}

/**
 * 에이전트에서 태그 제거
 */
function removeAgentTag($conn, $agentId, $tagId = null) {
    if ($tagId === null) {
        $stmt = $conn->prepare("DELETE FROM agent_tag_mapping WHERE agent_id = ?");
        $stmt->bind_param("s", $agentId);
    } else {
        $stmt = $conn->prepare("DELETE FROM agent_tag_mapping WHERE agent_id = ? AND tag_id = ?");
        $stmt->bind_param("si", $agentId, $tagId);
    }
    $result = $stmt->execute();
    $stmt->close();
    return $result;
}

/**
 * 에이전트의 그룹 목록 조회
 */
function getAgentGroups($conn, $agentId) {
    $stmt = $conn->prepare("
        SELECT ag.* FROM asset_groups ag
        JOIN agent_group_mapping agm ON ag.id = agm.group_id
        WHERE agm.agent_id = ?
        ORDER BY ag.sort_order, ag.name
    ");
    $stmt->bind_param("s", $agentId);
    $stmt->execute();
    $result = $stmt->get_result();
    $groups = $result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
    return $groups;
}

/**
 * 에이전트의 태그 목록 조회
 */
function getAgentTags($conn, $agentId) {
    $stmt = $conn->prepare("
        SELECT at.* FROM asset_tags at
        JOIN agent_tag_mapping atm ON at.id = atm.tag_id
        WHERE atm.agent_id = ?
        ORDER BY at.category, at.name
    ");
    $stmt->bind_param("s", $agentId);
    $stmt->execute();
    $result = $stmt->get_result();
    $tags = $result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
    return $tags;
}

/**
 * 그룹 또는 태그로 에이전트 필터링
 */
function getAgentsByFilter($conn, $groupId = null, $tagIds = [], $status = null) {
    $sql = "
        SELECT DISTINCT a.* FROM agents a
        LEFT JOIN agent_group_mapping agm ON a.agent_id = agm.agent_id
        LEFT JOIN agent_tag_mapping atm ON a.agent_id = atm.agent_id
        WHERE 1=1
    ";
    $params = [];
    $types = "";

    if ($groupId !== null) {
        $sql .= " AND agm.group_id = ?";
        $params[] = $groupId;
        $types .= "i";
    }

    if (!empty($tagIds)) {
        $placeholders = implode(',', array_fill(0, count($tagIds), '?'));
        $sql .= " AND atm.tag_id IN ($placeholders)";
        foreach ($tagIds as $tagId) {
            $params[] = $tagId;
            $types .= "i";
        }
    }

    if ($status !== null) {
        $sql .= " AND a.status = ?";
        $params[] = $status;
        $types .= "s";
    }

    $sql .= " ORDER BY a.hostname";

    $stmt = $conn->prepare($sql);
    if (!empty($params)) {
        $stmt->bind_param($types, ...$params);
    }
    $stmt->execute();
    $result = $stmt->get_result();
    $agents = $result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
    return $agents;
}

/**
 * 그룹별 취약점 통계 조회
 */
function getVulnStatsByGroup($conn, $groupId) {
    $stmt = $conn->prepare("
        SELECT
            SUM(sh.critical_count) as total_critical,
            SUM(sh.high_count) as total_high,
            SUM(sh.medium_count) as total_medium,
            SUM(sh.low_count) as total_low,
            COUNT(DISTINCT sh.id) as total_scans,
            COUNT(DISTINCT sh.agent_id) as agent_count
        FROM scan_history sh
        JOIN agent_group_mapping agm ON sh.agent_id = agm.agent_id
        WHERE agm.group_id = ? AND sh.scan_date > DATE_SUB(NOW(), INTERVAL 24 HOUR)
    ");
    $stmt->bind_param("i", $groupId);
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    return $result;
}

/**
 * 태그별 취약점 통계 조회
 */
function getVulnStatsByTag($conn, $tagId) {
    $stmt = $conn->prepare("
        SELECT
            SUM(sh.critical_count) as total_critical,
            SUM(sh.high_count) as total_high,
            SUM(sh.medium_count) as total_medium,
            SUM(sh.low_count) as total_low,
            COUNT(DISTINCT sh.id) as total_scans,
            COUNT(DISTINCT sh.agent_id) as agent_count
        FROM scan_history sh
        JOIN agent_tag_mapping atm ON sh.agent_id = atm.agent_id
        WHERE atm.tag_id = ? AND sh.scan_date > DATE_SUB(NOW(), INTERVAL 24 HOUR)
    ");
    $stmt->bind_param("i", $tagId);
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    return $result;
}

// ========================================
// 🤖 Trivy Agent API 호출 함수
// ========================================

/**
 * 에이전트 사용 여부 확인
 */
function isAgentEnabled() {
    $url = getenv('TRIVY_AGENT_URL');
    // 환경변수가 없거나 'disabled'면 사용 안함
    if (!$url || $url === 'disabled' || $url === 'false') {
        return false;
    }
    return true;
}

/**
 * 에이전트 API URL 가져오기
 */
function getAgentUrl() {
    return getenv('TRIVY_AGENT_URL') ?: 'http://trivy-agent:8888';
}

/**
 * 에이전트 API 토큰 가져오기
 */
function getAgentToken() {
    return getenv('AGENT_API_TOKEN') ?: 'default-agent-token-change-me';
}

/**
 * 에이전트 API 호출
 * @param string $endpoint API 엔드포인트 (예: /scan/image)
 * @param array $data POST 데이터
 * @param int $timeout 타임아웃 (초)
 * @return array ['success' => bool, 'data' => mixed, 'error' => string]
 */
function callAgentAPI($endpoint, $data = [], $timeout = 300) {
    $url = getAgentUrl() . $endpoint;
    $token = getAgentToken();

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode($data),
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json',
            'X-Agent-Token: ' . $token
        ],
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_CONNECTTIMEOUT => 10
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    // PHP 8.0+ 에서 curl_close()는 더 이상 필요 없음 (자동 정리됨)
    unset($ch);

    if ($error) {
        return ['success' => false, 'error' => 'cURL error: ' . $error, 'data' => null];
    }

    if ($httpCode !== 200) {
        return ['success' => false, 'error' => "HTTP $httpCode", 'data' => null];
    }

    $decoded = json_decode($response, true);
    if ($decoded === null) {
        return ['success' => false, 'error' => 'Invalid JSON response', 'data' => $response];
    }

    return $decoded;
}

/**
 * 에이전트로 이미지 스캔 (폴백: 직접 실행)
 * @param string $image 이미지명
 * @param string $severity 심각도 (예: HIGH,CRITICAL)
 * @param string $securityChecks 보안 체크 (예: vuln,config)
 * @return array Trivy 스캔 결과
 */
function scanImageViaAgent($image, $severity = 'HIGH,CRITICAL', $securityChecks = 'vuln,config') {
    // 에이전트 사용 시 API 호출
    if (isAgentEnabled()) {
        $result = callAgentAPI('/scan/image', [
            'image' => $image,
            'severity' => $severity,
            'security_checks' => $securityChecks
        ]);

        // 에이전트 성공 시 반환
        if ($result['success']) {
            return $result;
        }
        // 에이전트 실패 시 폴백으로 직접 실행
        error_log("Agent scan failed, falling back to direct execution: " . ($result['error'] ?? 'unknown'));
    }

    // 직접 Trivy 실행 (폴백)
    return scanImageDirectly($image, $severity, $securityChecks);
}

/**
 * Trivy 직접 실행 (에이전트 없이)
 */
function scanImageDirectly($image, $severity = 'HIGH,CRITICAL', $securityChecks = 'vuln,config') {
    $safeImage = escapeshellarg($image);
    $safeSeverity = escapeshellarg($severity);

    $command = "trivy image --security-checks $securityChecks --severity $safeSeverity --format json $safeImage 2>/dev/null";
    exec($command, $output, $resultCode);

    $jsonOutput = implode("\n", $output);

    // JSON 시작 위치 찾기
    $jsonStart = strpos($jsonOutput, '{');
    if ($jsonStart !== false && $jsonStart > 0) {
        $jsonOutput = substr($jsonOutput, $jsonStart);
    }

    $data = json_decode($jsonOutput, true);

    if ($data === null) {
        return ['success' => false, 'error' => 'Failed to parse Trivy output', 'result' => null];
    }

    return ['success' => true, 'result' => $data];
}

/**
 * 에이전트로 SBOM 생성 (폴백: 직접 실행)
 * @param string $image 이미지명
 * @param string $format SBOM 포맷 (cyclonedx, spdx, spdx-json)
 * @return array SBOM 결과
 */
function generateSbomViaAgent($image, $format = 'cyclonedx') {
    // 에이전트 사용 시 API 호출
    if (isAgentEnabled()) {
        $result = callAgentAPI('/scan/sbom', [
            'image' => $image,
            'format' => $format
        ]);

        if ($result['success']) {
            return $result;
        }
        error_log("Agent SBOM failed, falling back to direct execution: " . ($result['error'] ?? 'unknown'));
    }

    // 직접 Trivy 실행 (폴백)
    return generateSbomDirectly($image, $format);
}

/**
 * SBOM 직접 생성 (에이전트 없이)
 */
function generateSbomDirectly($image, $format = 'cyclonedx') {
    $safeImage = escapeshellarg($image);

    $command = "trivy image --format $format $safeImage 2>/dev/null";
    exec($command, $output, $resultCode);

    $result = implode("\n", $output);

    // JSON 시작 위치 찾기
    $jsonStart = strpos($result, '{');
    if ($jsonStart !== false && $jsonStart > 0) {
        $result = substr($result, $jsonStart);
    }

    if (empty($result)) {
        return ['success' => false, 'error' => 'SBOM generation failed', 'sbom' => null];
    }

    return ['success' => true, 'sbom' => $result];
}

/**
 * 에이전트로 설정 스캔
 * @param string $image 이미지명
 * @return array 설정 스캔 결과
 */
function scanConfigViaAgent($image) {
    return callAgentAPI('/scan/config', [
        'image' => $image,
        'security_checks' => 'config'
    ]);
}

/**
 * 에이전트 헬스체크
 * @return bool 정상 여부
 */
function checkAgentHealth() {
    $url = getAgentUrl() . '/health';
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 5,
        CURLOPT_CONNECTTIMEOUT => 3
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    unset($ch);

    return $httpCode === 200;
}

