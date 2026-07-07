<?php
/**
 * CSOP Lab — Finding Lifecycle
 *
 * Sandbox for CVE state management (open → reviewing → mitigated → fixed,
 * accepted_risk, false_positive, reopened) with risk-decision / owner /
 * evidence fields, before the model moves into MORI's Risk Register.
 * See docs/CSOP_LAB_SCOPE.md.
 */
require_once 'db_functions.php';

$conn = getDbConnection();
if ($conn) {
    initDatabase($conn);
    ensureFindingLifecycleTable($conn);
}

$action = $_GET['action'] ?? '';

// 이미지 목록
if ($action === 'images') {
    header('Content-Type: application/json');
    echo json_encode($conn ? getScanHistoryByImage($conn) : []);
    exit;
}

// 최신 스캔의 findings + lifecycle 상태 병합
if ($action === 'findings' && isset($_GET['image'])) {
    header('Content-Type: application/json');
    $image = $_GET['image'];
    $out = ['findings' => [], 'counts' => getFindingLifecycleCounts($conn, $image), 'states' => FINDING_LIFECYCLE_STATES()];
    $scans = $conn ? getRecentScansForImage($conn, $image, 1) : [];
    if (!empty($scans)) {
        $vulns = getScanVulnerabilities($conn, $scans[0]['id']);
        $life = getFindingLifecycle($conn, $image);
        foreach ($vulns as $v) {
            $key = ($v['vulnerability'] ?? '') . '|' . ($v['library'] ?? '');
            $lc = $life[$key] ?? null;
            $out['findings'][] = [
                'vulnerability_id' => $v['vulnerability'] ?? '',
                'package_name'     => $v['library'] ?? '',
                'severity'         => strtoupper($v['severity'] ?? 'UNKNOWN'),
                'fixed_version'    => $v['fixed_version'] ?? '',
                'state'            => $lc['state'] ?? 'open',
                'risk_decision'    => $lc['risk_decision'] ?? '',
                'owner'            => $lc['owner'] ?? '',
                'decision_reason'  => $lc['decision_reason'] ?? '',
                'due_date'         => $lc['due_date'] ?? '',
                'review_date'      => $lc['review_date'] ?? '',
                'evidence_note'    => $lc['evidence_note'] ?? '',
                'updated_at'       => $lc['updated_at'] ?? '',
            ];
        }
    }
    echo json_encode($out);
    exit;
}

// 상태 저장 (POST JSON)
if ($action === 'update' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    $body = json_decode(file_get_contents('php://input'), true) ?: [];
    $by = $_SESSION['username'] ?? 'admin';
    $ok = $conn ? upsertFindingLifecycle($conn, $body, $by) : false;
    echo json_encode(['success' => (bool)$ok]);
    exit;
}

$images = $conn ? getScanHistoryByImage($conn) : [];
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>CSOP Lab — Finding Lifecycle</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; color: #222; }
        .container { max-width: 1500px; margin: 0 auto; }
        h1, h2 { color: #333; }
        .lab-tag { display: inline-block; background: #6f42c1; color: #fff; font-size: 11px; padding: 2px 8px; border-radius: 4px; vertical-align: middle; margin-left: 8px; }
        .back-link { margin-bottom: 16px; }
        .back-link a { color: #007bff; text-decoration: none; margin-right: 15px; }
        .grid { display: grid; grid-template-columns: 320px 1fr; gap: 20px; }
        .card { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.08); }
        .image-list { max-height: 680px; overflow-y: auto; }
        .image-item { padding: 12px; border-bottom: 1px solid #eee; cursor: pointer; }
        .image-item:hover { background: #f0f7ff; }
        .image-item.active { background: #ede7f6; border-left: 3px solid #6f42c1; }
        .image-name { font-weight: bold; word-break: break-all; }
        .image-meta { font-size: 12px; color: #666; margin-top: 4px; }
        .counts { display: flex; gap: 8px; flex-wrap: wrap; margin: 12px 0; }
        .cpill { padding: 5px 10px; border-radius: 14px; font-size: 12px; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13px; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #eee; vertical-align: top; }
        th { background: #f8f9fa; }
        .badge { padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; color: #fff; }
        .critical { background: #dc3545; } .high { background: #fd7e14; }
        .medium { background: #ffc107; color: #333; } .low { background: #28a745; } .unknown { background: #6c757d; }
        select, input, textarea { padding: 5px; border: 1px solid #ccc; border-radius: 4px; font-size: 12px; width: 100%; }
        textarea { resize: vertical; min-height: 34px; }
        .st-open { background:#e2e3e5;color:#41464b; } .st-reviewing { background:#cff4fc;color:#055160; }
        .st-mitigated { background:#fff3cd;color:#664d03; } .st-fixed { background:#d1e7dd;color:#0f5132; }
        .st-accepted_risk { background:#f8d7da;color:#842029; } .st-false_positive { background:#e2e3e5;color:#41464b; }
        .st-reopened { background:#ffe0b2;color:#7a3e00; }
        .btn { padding: 6px 12px; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; background:#6f42c1; color:#fff; }
        .saved { color:#0f5132; font-size:11px; margin-left:6px; }
        .no-data, .loading { text-align: center; padding: 30px; color: #666; }
        .fields { display:grid; grid-template-columns: repeat(2, 1fr); gap:5px; margin-top:5px; }
        .hint { color:#666; font-size:12px; }
        details { margin-top:4px; }
        summary { cursor:pointer; font-size:12px; color:#6f42c1; }
    </style>
</head>
<body>
    <div class="container">
        <div class="back-link">
            <a href="index.php">← 메인</a>
            <a href="csop_scan_diff.php">Scan Diff V2</a>
            <a href="scan_history.php">스캔 기록</a>
        </div>
        <h1>🧭 Finding Lifecycle <span class="lab-tag">CSOP LAB</span></h1>
        <p class="hint" style="margin-top:-6px;">CVE 상태(open/accepted_risk/…)와 조치 결정·증적을 관리합니다. accepted_risk는 감사 증적으로 중요합니다.</p>

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
        let currentImage = null, states = [], findings = [];
        const stateLabel = {open:'Open',reviewing:'Reviewing',mitigated:'Mitigated',accepted_risk:'Accepted Risk',false_positive:'False Positive',fixed:'Fixed',reopened:'Reopened'};

        async function selectImage(name, el) {
            currentImage = name;
            document.querySelectorAll('.image-item').forEach(e => e.classList.remove('active'));
            if (el) el.classList.add('active');
            document.getElementById('content').innerHTML = '<div class="loading">로딩 중…</div>';
            const d = await (await fetch('?action=findings&image=' + encodeURIComponent(name))).json();
            states = d.states || [];
            render(name, d);
        }

        function render(name, d) {
            findings = d.findings || [];
            if (!d.findings || d.findings.length === 0) {
                document.getElementById('content').innerHTML = `<h2>${esc(name)}</h2><div class="no-data">최신 스캔에 취약점이 없습니다.</div>`;
                return;
            }
            const c = d.counts || {};
            const pills = states.map(s => `<span class="cpill st-${s}">${stateLabel[s]||s}: ${c[s]||0}</span>`).join('');

            let rows = '';
            d.findings.forEach((f, i) => {
                const sev = (f.severity||'').toLowerCase();
                const opts = states.map(s => `<option value="${s}" ${f.state===s?'selected':''}>${stateLabel[s]||s}</option>`).join('');
                rows += `<tr id="row-${i}" class="st-${f.state}">
                    <td><span class="badge ${sev}">${f.severity}</span></td>
                    <td>${esc(f.package_name)}</td>
                    <td>${esc(f.vulnerability_id)}<div class="hint">fix: ${esc(f.fixed_version)||'-'}</div></td>
                    <td>
                        <select id="state-${i}" onchange="document.getElementById('row-'+${i}).className='st-'+this.value">${opts}</select>
                        <details>
                            <summary>세부/증적</summary>
                            <div class="fields">
                                <select id="decision-${i}" title="risk_decision">
                                    <option value="">(decision)</option>
                                    ${['mitigate','accept','transfer','avoid'].map(x=>`<option ${f.risk_decision===x?'selected':''}>${x}</option>`).join('')}
                                </select>
                                <input id="owner-${i}" placeholder="owner" value="${esc(f.owner)}">
                                <input id="due-${i}" type="date" title="due_date" value="${esc(f.due_date)}">
                                <input id="review-${i}" type="date" title="review_date" value="${esc(f.review_date)}">
                            </div>
                            <input id="reason-${i}" placeholder="decision_reason" value="${esc(f.decision_reason)}" style="margin-top:5px;">
                            <textarea id="note-${i}" placeholder="evidence_note" style="margin-top:5px;">${esc(f.evidence_note)}</textarea>
                        </details>
                    </td>
                    <td>
                        <button class="btn" onclick="save(${i})">저장</button>
                        <span class="saved" id="saved-${i}">${f.updated_at?('· '+f.updated_at):''}</span>
                    </td>
                </tr>`;
            });

            document.getElementById('content').innerHTML = `
                <h2 style="word-break:break-all;">${esc(name)}</h2>
                <div class="counts">${pills}</div>
                <table><thead><tr><th>Sev</th><th>Package</th><th>CVE</th><th>State / 세부</th><th></th></tr></thead>
                <tbody>${rows}</tbody></table>`;
        }

        async function save(i) {
            const src = findings[i];
            const f = {
                image_name: currentImage,
                vulnerability_id: src.vulnerability_id,
                package_name: src.package_name,
                state: val('state-'+i), risk_decision: val('decision-'+i), owner: val('owner-'+i),
                decision_reason: val('reason-'+i), due_date: val('due-'+i), review_date: val('review-'+i),
                evidence_note: val('note-'+i),
            };
            const r = await (await fetch('?action=update', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(f)})).json();
            const el = document.getElementById('saved-'+i);
            el.textContent = r.success ? '✓ 저장됨' : '✗ 실패';
            if (r.success) selectImage(currentImage, null); // refresh counts
        }
        function val(id){ const e=document.getElementById(id); return e ? e.value : ''; }
        function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
    </script>
</body>
</html>
