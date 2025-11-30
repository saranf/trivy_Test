<?php
require_once 'db_functions.php';

$conn = getDbConnection();
if ($conn) {
    initDatabase($conn);
}

$action = $_GET['action'] ?? '';

// API: 이미지별 스캔 목록
if ($action === 'images') {
    header('Content-Type: application/json');
    echo json_encode($conn ? getScanHistoryByImage($conn) : []);
    exit;
}

// API: 특정 이미지의 스캔 기록
if ($action === 'scans' && isset($_GET['image'])) {
    header('Content-Type: application/json');
    echo json_encode($conn ? getScansForImage($conn, $_GET['image']) : []);
    exit;
}

// API: 두 스캔 비교 (diff)
if ($action === 'diff') {
    header('Content-Type: application/json');
    $oldId = (int)($_GET['old'] ?? 0);
    $newId = (int)($_GET['new'] ?? 0);
    
    if ($oldId && $newId && $conn) {
        echo json_encode(calculateScanDiff($conn, $oldId, $newId));
    } else {
        echo json_encode(['error' => 'Invalid scan IDs']);
    }
    exit;
}

// API: 자동 diff (이미지의 최근 2개 스캔 비교)
if ($action === 'auto_diff' && isset($_GET['image'])) {
    header('Content-Type: application/json');
    $scans = $conn ? getRecentScansForImage($conn, $_GET['image'], 2) : [];
    
    if (count($scans) >= 2) {
        $diff = calculateScanDiff($conn, $scans[1]['id'], $scans[0]['id']);
        $diff['old_scan'] = $scans[1];
        $diff['new_scan'] = $scans[0];
        echo json_encode($diff);
    } else {
        echo json_encode(['error' => 'Need at least 2 scans for diff', 'scan_count' => count($scans)]);
    }
    exit;
}

$images = $conn ? getScanHistoryByImage($conn) : [];
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>스캔 모니터링</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; }
        h1, h2 { color: #333; }
        .back-link { margin-bottom: 20px; }
        .back-link a { color: #007bff; text-decoration: none; margin-right: 15px; }
        .grid { display: grid; grid-template-columns: 350px 1fr; gap: 20px; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .image-list { max-height: 600px; overflow-y: auto; }
        .image-item { padding: 12px; border-bottom: 1px solid #eee; cursor: pointer; transition: background 0.2s; }
        .image-item:hover { background: #f0f7ff; }
        .image-item.active { background: #e3f2fd; border-left: 3px solid #007bff; }
        .image-name { font-weight: bold; word-break: break-all; }
        .image-meta { font-size: 12px; color: #666; margin-top: 5px; }
        .badge { padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; color: white; }
        .critical { background: #dc3545; }
        .high { background: #fd7e14; }
        .medium { background: #ffc107; color: #333; }
        .low { background: #28a745; }
        .added { background: #28a745; }
        .removed { background: #dc3545; }
        .btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-size: 13px; margin-right: 5px; }
        .btn-primary { background: #007bff; color: white; }
        .btn-success { background: #28a745; color: white; }
        .btn-secondary { background: #6c757d; color: white; }
        .diff-section { margin-top: 20px; }
        .diff-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .diff-stats { display: flex; gap: 20px; margin-bottom: 15px; }
        .stat-box { padding: 15px 25px; border-radius: 8px; text-align: center; }
        .stat-box.added-box { background: #d4edda; color: #155724; }
        .stat-box.removed-box { background: #f8d7da; color: #721c24; }
        .stat-box.unchanged-box { background: #e2e3e5; color: #383d41; }
        .stat-number { font-size: 28px; font-weight: bold; }
        .stat-label { font-size: 12px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; }
        .no-data { text-align: center; padding: 40px; color: #666; }
        .loading { text-align: center; padding: 20px; color: #666; }
        .scan-selector { display: flex; gap: 10px; margin-bottom: 15px; }
        .scan-selector select { flex: 1; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        .refresh-btn { position: fixed; bottom: 30px; right: 30px; padding: 15px 20px; background: #007bff; color: white; border: none; border-radius: 50px; cursor: pointer; box-shadow: 0 4px 12px rgba(0,0,0,0.2); }
    </style>
</head>
<body>
    <div class="container">
        <div class="back-link">
            <a href="index.html">← 메인으로</a>
            <a href="container_scan.php">컨테이너 스캔</a>
            <a href="scan_history.php">스캔 기록</a>
        </div>
        <h1>📊 스캔 모니터링 & Diff</h1>
        
        <div class="grid">
            <div class="card image-list">
                <h2>이미지 목록</h2>
                <?php if (empty($images)): ?>
                    <div class="no-data">스캔 기록이 없습니다.</div>
                <?php else: ?>
                    <?php foreach ($images as $img): ?>
                    <div class="image-item" onclick="selectImage('<?= htmlspecialchars($img['image_name'], ENT_QUOTES) ?>')">
                        <div class="image-name"><?= htmlspecialchars($img['image_name']) ?></div>
                        <div class="image-meta">
                            스캔 <?= $img['scan_count'] ?>회 | 마지막: <?= $img['last_scan'] ?>
                        </div>
                    </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
            
            <div class="card">
                <div id="diff-content">
                    <div class="no-data">왼쪽에서 이미지를 선택하세요.</div>
                </div>
            </div>
        </div>
    </div>
    
    <button class="refresh-btn" onclick="location.reload()">🔄 새로고침</button>

    <script>
        let currentImage = null;
        let scans = [];

        async function selectImage(imageName) {
            currentImage = imageName;
            document.querySelectorAll('.image-item').forEach(el => el.classList.remove('active'));
            event.currentTarget.classList.add('active');

            document.getElementById('diff-content').innerHTML = '<div class="loading">로딩 중...</div>';

            // 해당 이미지의 스캔 기록 가져오기
            const res = await fetch('?action=scans&image=' + encodeURIComponent(imageName));
            scans = await res.json();

            if (scans.length < 2) {
                document.getElementById('diff-content').innerHTML = `
                    <h2>${imageName}</h2>
                    <div class="no-data">Diff를 보려면 최소 2회 스캔이 필요합니다. (현재 ${scans.length}회)</div>
                `;
                return;
            }

            // 스캔 선택 UI 렌더링
            renderScanSelector();
            loadDiff(scans[1].id, scans[0].id);
        }

        function renderScanSelector() {
            let options = scans.map(s =>
                `<option value="${s.id}">[${s.scan_date}] C:${s.critical_count} H:${s.high_count} M:${s.medium_count} L:${s.low_count}</option>`
            ).join('');

            document.getElementById('diff-content').innerHTML = `
                <h2>${currentImage}</h2>
                <div class="scan-selector">
                    <div><label>이전 스캔:</label><select id="oldScan">${options}</select></div>
                    <div><label>최신 스캔:</label><select id="newScan">${options}</select></div>
                    <button class="btn btn-primary" onclick="compareSel()">비교</button>
                </div>
                <div id="diff-result"><div class="loading">로딩 중...</div></div>
            `;

            document.getElementById('oldScan').selectedIndex = 1;
            document.getElementById('newScan').selectedIndex = 0;
        }

        function compareSel() {
            const oldId = document.getElementById('oldScan').value;
            const newId = document.getElementById('newScan').value;
            loadDiff(oldId, newId);
        }

        async function loadDiff(oldId, newId) {
            const res = await fetch(`?action=diff&old=${oldId}&new=${newId}`);
            const diff = await res.json();
            renderDiff(diff);
        }

        function renderDiff(diff) {
            const s = diff.summary;
            let html = `
                <div class="diff-stats">
                    <div class="stat-box removed-box"><div class="stat-number">+${s.added_count}</div><div class="stat-label">새 취약점</div></div>
                    <div class="stat-box added-box"><div class="stat-number">-${s.removed_count}</div><div class="stat-label">해결됨</div></div>
                    <div class="stat-box unchanged-box"><div class="stat-number">${s.unchanged_count}</div><div class="stat-label">유지</div></div>
                </div>
            `;

            if (diff.added.length > 0) {
                html += `<h3 style="color:#dc3545;">🆕 새로 발견된 취약점 (${diff.added.length})</h3>`;
                html += renderVulnTable(diff.added);
            }

            if (diff.removed.length > 0) {
                html += `<h3 style="color:#28a745;">✅ 해결된 취약점 (${diff.removed.length})</h3>`;
                html += renderVulnTable(diff.removed);
            }

            if (s.added_count === 0 && s.removed_count === 0) {
                html += '<div class="no-data">변경된 취약점이 없습니다.</div>';
            }

            document.getElementById('diff-result').innerHTML = html;
        }

        function renderVulnTable(vulns) {
            let html = '<table><thead><tr><th>Library</th><th>Vulnerability</th><th>Severity</th><th>Version</th><th>Fixed</th></tr></thead><tbody>';
            vulns.forEach(v => {
                const sev = (v.severity || '').toLowerCase();
                html += `<tr>
                    <td>${v.library}</td>
                    <td>${v.vulnerability}</td>
                    <td><span class="badge ${sev}">${v.severity}</span></td>
                    <td>${v.installed_version}</td>
                    <td>${v.fixed_version || '-'}</td>
                </tr>`;
            });
            html += '</tbody></table>';
            return html;
        }
    </script>
</body>
</html>

