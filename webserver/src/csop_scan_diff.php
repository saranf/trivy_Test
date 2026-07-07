<?php
/**
 * CSOP Lab — Scan Diff V2
 *
 * Before/after comparison of two Trivy scans of the same image, classified as
 * new / fixed / unchanged / severity_changed / version_changed / reopened, with
 * MORI evidence export (JSON envelope + CSV). See docs/CSOP_LAB_SCOPE.md.
 */
require_once 'db_functions.php';

$conn = getDbConnection();
if ($conn) {
    initDatabase($conn);
}

$action = $_GET['action'] ?? '';

if ($action === 'images') {
    header('Content-Type: application/json');
    echo json_encode($conn ? getScanHistoryByImage($conn) : []);
    exit;
}

if ($action === 'scans' && isset($_GET['image'])) {
    header('Content-Type: application/json');
    echo json_encode($conn ? getScansForImage($conn, $_GET['image']) : []);
    exit;
}

if ($action === 'diff2') {
    header('Content-Type: application/json');
    $oldId = (int)($_GET['old'] ?? 0);
    $newId = (int)($_GET['new'] ?? 0);
    if ($oldId && $newId && $conn) {
        echo json_encode(calculateScanDiffV2($conn, $oldId, $newId));
    } else {
        echo json_encode(['error' => 'Invalid scan IDs']);
    }
    exit;
}

$images = $conn ? getScanHistoryByImage($conn) : [];
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>CSOP Lab — Scan Diff V2</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; color: #222; }
        .container { max-width: 1400px; margin: 0 auto; }
        h1, h2, h3 { color: #333; }
        .lab-tag { display: inline-block; background: #6f42c1; color: #fff; font-size: 11px; padding: 2px 8px; border-radius: 4px; vertical-align: middle; margin-left: 8px; }
        .back-link { margin-bottom: 16px; }
        .back-link a { color: #007bff; text-decoration: none; margin-right: 15px; }
        .grid { display: grid; grid-template-columns: 340px 1fr; gap: 20px; }
        .card { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.08); }
        .image-list { max-height: 640px; overflow-y: auto; }
        .image-item { padding: 12px; border-bottom: 1px solid #eee; cursor: pointer; }
        .image-item:hover { background: #f0f7ff; }
        .image-item.active { background: #ede7f6; border-left: 3px solid #6f42c1; }
        .image-name { font-weight: bold; word-break: break-all; }
        .image-meta { font-size: 12px; color: #666; margin-top: 4px; }
        .scan-selector { display: flex; gap: 10px; align-items: flex-end; flex-wrap: wrap; margin-bottom: 16px; }
        .scan-selector label { font-size: 12px; color: #555; display: block; margin-bottom: 3px; }
        .scan-selector select { padding: 8px; border: 1px solid #ddd; border-radius: 4px; min-width: 240px; }
        .btn { padding: 8px 14px; border: none; border-radius: 4px; cursor: pointer; font-size: 13px; }
        .btn-primary { background: #6f42c1; color: #fff; }
        .btn-export { background: #0d6efd; color: #fff; }
        .btn-export.csv { background: #198754; }
        .cards { display: flex; gap: 12px; flex-wrap: wrap; margin: 16px 0; }
        .delta-card { padding: 14px 18px; border-radius: 8px; text-align: center; min-width: 96px; }
        .delta-card .n { font-size: 26px; font-weight: bold; }
        .delta-card .l { font-size: 11px; text-transform: uppercase; letter-spacing: .5px; }
        .c-new { background: #f8d7da; color: #842029; }
        .c-reopened { background: #ffe0b2; color: #7a3e00; }
        .c-fixed { background: #d1e7dd; color: #0f5132; }
        .c-sev { background: #fff3cd; color: #664d03; }
        .c-ver { background: #cff4fc; color: #055160; }
        .c-unchanged { background: #e2e3e5; color: #41464b; }
        table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13px; }
        th, td { padding: 9px 10px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; position: sticky; top: 0; }
        .badge { padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; color: #fff; }
        .critical { background: #dc3545; } .high { background: #fd7e14; }
        .medium { background: #ffc107; color: #333; } .low { background: #28a745; } .unknown { background: #6c757d; }
        .dt { padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }
        .dt-new { background: #f8d7da; color: #842029; } .dt-reopened { background: #ffe0b2; color: #7a3e00; }
        .dt-fixed { background: #d1e7dd; color: #0f5132; } .dt-severity_changed { background: #fff3cd; color: #664d03; }
        .dt-version_changed { background: #cff4fc; color: #055160; } .dt-unchanged { background: #e2e3e5; color: #41464b; }
        .filters { margin: 10px 0; font-size: 13px; }
        .filters label { margin-right: 14px; cursor: pointer; }
        .no-data, .loading { text-align: center; padding: 36px; color: #666; }
        .toolbar { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="back-link">
            <a href="index.php">← 메인</a>
            <a href="scan_monitor.php">스캔 모니터링</a>
            <a href="scan_history.php">스캔 기록</a>
        </div>
        <h1>🔍 Scan Diff V2 <span class="lab-tag">CSOP LAB</span></h1>
        <p style="color:#666;margin-top:-6px;">조치 전/후 취약점 변화를 분류하고 MORI evidence(JSON/CSV)로 내보냅니다.</p>

        <div class="grid">
            <div class="card image-list">
                <h2>이미지</h2>
                <?php if (empty($images)): ?>
                    <div class="no-data">스캔 기록이 없습니다.</div>
                <?php else: ?>
                    <?php foreach ($images as $img): ?>
                    <div class="image-item" onclick="selectImage('<?= htmlspecialchars($img['image_name'], ENT_QUOTES) ?>', this)">
                        <div class="image-name"><?= htmlspecialchars($img['image_name']) ?></div>
                        <div class="image-meta">스캔 <?= (int)$img['scan_count'] ?>회 · 마지막 <?= htmlspecialchars($img['last_scan']) ?></div>
                    </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>

            <div class="card">
                <div id="content"><div class="no-data">왼쪽에서 이미지를 선택하세요.</div></div>
            </div>
        </div>
    </div>

    <script>
        let scans = [], currentImage = null, lastDiff = null, activeFilter = 'all';

        async function selectImage(name, el) {
            currentImage = name;
            document.querySelectorAll('.image-item').forEach(e => e.classList.remove('active'));
            if (el) el.classList.add('active');
            document.getElementById('content').innerHTML = '<div class="loading">로딩 중…</div>';

            scans = await (await fetch('?action=scans&image=' + encodeURIComponent(name))).json();
            if (!Array.isArray(scans) || scans.length < 2) {
                document.getElementById('content').innerHTML =
                    `<h2>${esc(name)}</h2><div class="no-data">Diff에는 최소 2회 스캔이 필요합니다 (현재 ${scans.length || 0}회).</div>`;
                return;
            }
            const opts = scans.map(s =>
                `<option value="${s.id}">[${s.scan_date}] C:${s.critical_count} H:${s.high_count} M:${s.medium_count} L:${s.low_count}</option>`).join('');
            document.getElementById('content').innerHTML = `
                <div class="toolbar">
                    <h2 style="margin:0;word-break:break-all;">${esc(name)}</h2>
                </div>
                <div class="scan-selector">
                    <div><label>이전 스캔 (before)</label><select id="oldScan">${opts}</select></div>
                    <div><label>최신 스캔 (after)</label><select id="newScan">${opts}</select></div>
                    <button class="btn btn-primary" onclick="compare()">비교</button>
                </div>
                <div id="result"><div class="loading">로딩 중…</div></div>`;
            document.getElementById('oldScan').selectedIndex = 1;
            document.getElementById('newScan').selectedIndex = 0;
            compare();
        }

        function compare() {
            const o = document.getElementById('oldScan').value, n = document.getElementById('newScan').value;
            activeFilter = 'all';
            loadDiff(o, n);
        }

        async function loadDiff(oldId, newId) {
            const d = await (await fetch(`?action=diff2&old=${oldId}&new=${newId}`)).json();
            lastDiff = d; lastDiff._old = oldId; lastDiff._new = newId;
            render();
        }

        function render() {
            const d = lastDiff; if (!d || d.error) { document.getElementById('result').innerHTML = `<div class="no-data">${d && d.error || '오류'}</div>`; return; }
            const c = d.counts;
            const card = (cls, n, l) => `<div class="delta-card ${cls}"><div class="n">${n}</div><div class="l">${l}</div></div>`;
            const cardsHtml = `<div class="cards">
                ${card('c-new', c.new, 'New')}
                ${card('c-reopened', c.reopened, 'Reopened')}
                ${card('c-fixed', c.fixed, 'Fixed')}
                ${card('c-sev', c.severity_changed, 'Sev Δ')}
                ${card('c-ver', c.version_changed, 'Ver Δ')}
                ${card('c-unchanged', c.unchanged, 'Unchanged')}
            </div>`;

            const exp = `api/scan_diff_export.php?old=${d._old}&new=${d._new}`;
            const toolbar = `<div class="toolbar">
                <div class="filters">
                    <strong>필터:</strong>
                    <label><input type="radio" name="flt" ${activeFilter==='all'?'checked':''} onclick="setFilter('all')"> 전체</label>
                    <label><input type="radio" name="flt" ${activeFilter==='crithigh'?'checked':''} onclick="setFilter('crithigh')"> Critical/High</label>
                    <label><input type="radio" name="flt" ${activeFilter==='changed'?'checked':''} onclick="setFilter('changed')"> 변경분만</label>
                </div>
                <div>
                    <a class="btn btn-export" href="${exp}&format=json">⬇ MORI Evidence JSON</a>
                    <a class="btn btn-export csv" href="${exp}&format=csv">⬇ CSV</a>
                </div>
            </div>`;

            let rows = d.findings;
            if (activeFilter === 'crithigh') rows = rows.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
            if (activeFilter === 'changed') rows = rows.filter(f => f.delta_type !== 'unchanged');

            let table = '<table><thead><tr><th>Δ</th><th>Severity</th><th>Package</th><th>Vulnerability</th><th>Installed</th><th>Fixed</th></tr></thead><tbody>';
            if (rows.length === 0) table += '<tr><td colspan="6" class="no-data">표시할 항목이 없습니다.</td></tr>';
            rows.forEach(f => {
                const sev = (f.severity || '').toLowerCase();
                const sevCell = f.delta_type === 'severity_changed' && f.prev_severity
                    ? `<span class="badge ${(f.prev_severity||'').toLowerCase()}">${f.prev_severity}</span> → <span class="badge ${sev}">${f.severity}</span>`
                    : `<span class="badge ${sev}">${f.severity}</span>`;
                table += `<tr>
                    <td><span class="dt dt-${f.delta_type}">${f.delta_type}</span></td>
                    <td>${sevCell}</td>
                    <td>${esc(f.library)}</td>
                    <td>${esc(f.vulnerability)}</td>
                    <td>${esc(f.installed_version)}</td>
                    <td>${esc(f.fixed_version) || '-'}</td>
                </tr>`;
            });
            table += '</tbody></table>';
            document.getElementById('result').innerHTML = cardsHtml + toolbar + table;
        }

        function setFilter(f) { activeFilter = f; render(); }
        function esc(s) { return (s == null ? '' : String(s)).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
    </script>
</body>
</html>
