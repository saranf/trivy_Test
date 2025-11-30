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
            low_count INT DEFAULT 0
        )
    ");

    // 취약점 상세 테이블
    $conn->query("
        CREATE TABLE IF NOT EXISTS scan_vulnerabilities (
            id INT AUTO_INCREMENT PRIMARY KEY,
            scan_id INT NOT NULL,
            library VARCHAR(255),
            vulnerability VARCHAR(255),
            severity VARCHAR(50),
            installed_version VARCHAR(100),
            fixed_version VARCHAR(100),
            title TEXT,
            FOREIGN KEY (scan_id) REFERENCES scan_history(id) ON DELETE CASCADE
        )
    ");
}

// 스캔 결과 저장
function saveScanResult($conn, $imageName, $trivyData) {
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

    $stmt = $conn->prepare("INSERT INTO scan_history (image_name, total_vulns, critical_count, high_count, medium_count, low_count) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("siiiii", $imageName, $total, $counts['CRITICAL'], $counts['HIGH'], $counts['MEDIUM'], $counts['LOW']);
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

// 스캔 기록 목록 조회
function getScanHistory($conn) {
    $result = $conn->query("SELECT * FROM scan_history ORDER BY scan_date DESC LIMIT 100");
    $history = [];
    while ($row = $result->fetch_assoc()) {
        $history[] = $row;
    }
    return $history;
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

