<?php
// MySQL 연결 설정
function getDbConnection() {
    $host = "mysql";  // Docker 서비스 이름
    $username = "trivy_user";
    $password = "trivy_password";
    $dbname = "trivy_db";

    try {
        mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
        $conn = new mysqli($host, $username, $password, $dbname);
        return $conn;
    } catch (mysqli_sql_exception $e) {
        return null;
    }
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

    // 사용자 테이블 (RBAC)
    $conn->query("
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            role ENUM('viewer', 'operator', 'admin') NOT NULL DEFAULT 'viewer',
            email VARCHAR(100),
            is_active TINYINT(1) DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            last_login DATETIME,
            INDEX idx_username (username),
            INDEX idx_role (role)
        )
    ");

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
}

// 스캔 결과 저장 (scan_source: 'manual', 'auto', 'bulk')
function saveScanResult($conn, $imageName, $trivyData, $scanSource = 'manual') {
    $counts = ['CRITICAL' => 0, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0];
    $vulns = [];

    if (isset($trivyData['Results'])) {
        foreach ($trivyData['Results'] as $result) {
            if (isset($result['Vulnerabilities'])) {
                foreach ($result['Vulnerabilities'] as $v) {
                    $sev = $v['Severity'] ?? 'UNKNOWN';
                    if (isset($counts[$sev])) $counts[$sev]++;
                    $vulns[] = $v;
                }
            }
        }
    }

    $total = array_sum($counts);

    $stmt = $conn->prepare("INSERT INTO scan_history (image_name, total_vulns, critical_count, high_count, medium_count, low_count, scan_source) VALUES (?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("siiiiss", $imageName, $total, $counts['CRITICAL'], $counts['HIGH'], $counts['MEDIUM'], $counts['LOW'], $scanSource);
    $stmt->execute();
    $scanId = $conn->insert_id;
    $stmt->close();

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

    return $scanId;
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

