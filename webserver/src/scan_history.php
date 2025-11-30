<?php
header('Content-Type: text/html; charset=utf-8');

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

    // 취약점 상세 테이블 (기존 테이블 확장)
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
    // 취약점 카운트
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

    // 스캔 기록 저장
    $stmt = $conn->prepare("INSERT INTO scan_history (image_name, total_vulns, critical_count, high_count, medium_count, low_count) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("siiiii", $imageName, $total, $counts['CRITICAL'], $counts['HIGH'], $counts['MEDIUM'], $counts['LOW']);
    $stmt->execute();
    $scanId = $conn->insert_id;
    $stmt->close();

    // 취약점 상세 저장
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

$conn = getDbConnection();
if ($conn) {
    initDatabase($conn);
}

// API 처리
$action = $_GET['action'] ?? '';

if ($action === 'delete' && isset($_GET['id'])) {
    deleteScan($conn, (int)$_GET['id']);
    header('Location: scan_history.php');
    exit;
}

if ($action === 'csv' && isset($_GET['id'])) {
    $scanId = (int)$_GET['id'];
    $vulns = getScanVulnerabilities($conn, $scanId);

    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename=scan_' . $scanId . '.csv');

    $output = fopen('php://output', 'w');
    // UTF-8 BOM for Excel compatibility
    fprintf($output, chr(0xEF).chr(0xBB).chr(0xBF));
    fputcsv($output, ['Library', 'Vulnerability ID', 'Severity', 'Installed Version', 'Fixed Version', 'Title'], ',', '"', '\\');
    foreach ($vulns as $v) {
        fputcsv($output, [$v['library'], $v['vulnerability'], $v['severity'], $v['installed_version'], $v['fixed_version'], $v['title']], ',', '"', '\\');
    }
    fclose($output);
    exit;
}

if ($action === 'detail' && isset($_GET['id'])) {
    header('Content-Type: application/json');
    echo json_encode(getScanVulnerabilities($conn, (int)$_GET['id']));
    exit;
}

$history = $conn ? getScanHistory($conn) : [];
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>스캔 기록</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #333; }
        .back-link { margin-bottom: 20px; }
        .back-link a { color: #007bff; text-decoration: none; }
        table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; font-weight: 600; }
        tr:hover { background: #f5f5f5; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; color: white; }
        .critical { background: #dc3545; }
        .high { background: #fd7e14; }
        .medium { background: #ffc107; color: #333; }
        .low { background: #28a745; }
        .btn { padding: 6px 12px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; font-size: 13px; margin-right: 5px; }
        .btn-csv { background: #28a745; color: white; }
        .btn-delete { background: #dc3545; color: white; }
        .btn-detail { background: #007bff; color: white; }
        .no-data { text-align: center; padding: 40px; color: #666; }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; }
        .modal-content { background: white; margin: 50px auto; padding: 20px; border-radius: 8px; max-width: 90%; max-height: 80%; overflow: auto; }
        .modal-close { float: right; font-size: 24px; cursor: pointer; }
        .detail-table { font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="back-link"><a href="index.html">← 메인으로</a> | <a href="container_scan.php">컨테이너 스캔</a></div>
        <h1>📋 스캔 기록</h1>

        <?php if (empty($history)): ?>
            <div class="no-data">저장된 스캔 기록이 없습니다.</div>
        <?php else: ?>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>이미지</th>
                        <th>스캔 일시</th>
                        <th>총 취약점</th>
                        <th>CRITICAL</th>
                        <th>HIGH</th>
                        <th>MEDIUM</th>
                        <th>LOW</th>
                        <th>작업</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($history as $h): ?>
                    <tr>
                        <td><?= $h['id'] ?></td>
                        <td><?= htmlspecialchars($h['image_name']) ?></td>
                        <td><?= $h['scan_date'] ?></td>
                        <td><strong><?= $h['total_vulns'] ?></strong></td>
                        <td><span class="badge critical"><?= $h['critical_count'] ?></span></td>
                        <td><span class="badge high"><?= $h['high_count'] ?></span></td>
                        <td><span class="badge medium"><?= $h['medium_count'] ?></span></td>
                        <td><span class="badge low"><?= $h['low_count'] ?></span></td>
                        <td>
                            <button class="btn btn-detail" onclick="showDetail(<?= $h['id'] ?>)">상세</button>
                            <a href="?action=csv&id=<?= $h['id'] ?>" class="btn btn-csv">CSV</a>
                            <a href="?action=delete&id=<?= $h['id'] ?>" class="btn btn-delete" onclick="return confirm('삭제하시겠습니까?')">삭제</a>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>

    <div id="modal" class="modal">
        <div class="modal-content">
            <span class="modal-close" onclick="closeModal()">&times;</span>
            <h2>취약점 상세</h2>
            <div id="detail-content"></div>
        </div>
    </div>

    <script>
        async function showDetail(scanId) {
            const res = await fetch('?action=detail&id=' + scanId);
            const data = await res.json();

            let html = '<table class="detail-table"><thead><tr><th>Library</th><th>Vulnerability</th><th>Severity</th><th>Installed</th><th>Fixed</th><th>Title</th></tr></thead><tbody>';
            data.forEach(v => {
                const badgeClass = v.severity.toLowerCase();
                html += `<tr><td>${v.library}</td><td>${v.vulnerability}</td><td><span class="badge ${badgeClass}">${v.severity}</span></td><td>${v.installed_version}</td><td>${v.fixed_version || '-'}</td><td>${v.title || '-'}</td></tr>`;
            });
            html += '</tbody></table>';

            document.getElementById('detail-content').innerHTML = html;
            document.getElementById('modal').style.display = 'block';
        }

        function closeModal() {
            document.getElementById('modal').style.display = 'none';
        }

        window.onclick = function(e) {
            if (e.target == document.getElementById('modal')) closeModal();
        }
    </script>
</body>
</html>
