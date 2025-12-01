<?php
require_once 'db_functions.php';

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

$search = $_GET['search'] ?? '';
$sourceFilter = $_GET['source'] ?? '';
$history = $conn ? getScanHistory($conn, $search, $sourceFilter) : [];
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
        .tag { padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; }
        .tag-manual { background: #e3f2fd; color: #1565c0; }
        .tag-auto { background: #fff3e0; color: #e65100; }
        .tag-bulk { background: #f3e5f5; color: #7b1fa2; }
        .search-box { margin-bottom: 20px; display: flex; gap: 10px; align-items: center; background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .search-box input { padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; width: 300px; }
        .search-box select { padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }
        .search-box button { padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .search-box a { padding: 10px 15px; background: #6c757d; color: white; border-radius: 4px; text-decoration: none; font-size: 14px; }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; }
        .modal-content { background: white; margin: 50px auto; padding: 20px; border-radius: 8px; max-width: 90%; max-height: 80%; overflow: auto; }
        .modal-close { float: right; font-size: 24px; cursor: pointer; }
        .detail-table { font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="back-link"><a href="index.php">← 메인으로</a> | <a href="container_scan.php">컨테이너 스캔</a></div>
        <h1>📋 스캔 기록</h1>

        <div class="search-box">
            <form method="get" style="display: flex; gap: 10px; align-items: center;">
                <input type="text" name="search" placeholder="이미지명 검색..." value="<?= htmlspecialchars($search) ?>">
                <select name="source">
                    <option value="">전체 소스</option>
                    <option value="manual" <?= $sourceFilter === 'manual' ? 'selected' : '' ?>>수동 스캔</option>
                    <option value="auto" <?= $sourceFilter === 'auto' ? 'selected' : '' ?>>자동 스캔</option>
                    <option value="bulk" <?= $sourceFilter === 'bulk' ? 'selected' : '' ?>>일괄 스캔</option>
                </select>
                <button type="submit">검색</button>
                <a href="scan_history.php">초기화</a>
            </form>
        </div>

        <?php if (empty($history)): ?>
            <div class="no-data">저장된 스캔 기록이 없습니다.</div>
        <?php else: ?>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>소스</th>
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
                    <?php foreach ($history as $h):
                        $source = $h['scan_source'] ?? 'manual';
                        $sourceLabel = ['manual' => '수동', 'auto' => '자동', 'bulk' => '일괄'][$source] ?? $source;
                        $tagClass = "tag-$source";
                    ?>
                    <tr>
                        <td><?= $h['id'] ?></td>
                        <td><span class="tag <?= $tagClass ?>"><?= $sourceLabel ?></span></td>
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
