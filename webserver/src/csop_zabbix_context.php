<?php
/**
 * CSOP Lab — Zabbix Host Context (+ Host↔Image mapping)
 *
 * Correlates MORI-SOC's Zabbix hosts with CSOP Trivy scan diffs via an explicit
 * host↔image mapping. For each Zabbix host, mapped images show their latest
 * before/after diff (New / Fixed / Still-open) and link into Scan Diff V2.
 *
 * The mapping is also exposed as JSON (?action=mappings) so MORI can consume it
 * instead of deriving host_id from the Trivy ArtifactName.
 *
 * Reads MORI live: GET /zabbix/hosts, GET /vulnerabilities/risk-summary.
 * See docs/MORI_INTEGRATION.md, docs/CSOP_LAB_SCOPE.md.
 */
require_once 'db_functions.php';

$conn = getDbConnection();
if ($conn) { initDatabase($conn); ensureHostImageMappingTable($conn); }

$action = $_GET['action'] ?? '';
$by = $_SESSION['username'] ?? 'admin';

// --- mapping API ---------------------------------------------------------
if ($action === 'mappings') {                       // JSON for MORI / debugging
    header('Content-Type: application/json');
    echo json_encode($conn ? getHostImageMappings($conn) : []);
    exit;
}
if ($action === 'map_add' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    $ok = $conn ? upsertHostImageMapping(
        $conn, trim($_POST['hostname'] ?? ''), trim($_POST['image_name'] ?? ''),
        trim($_POST['agent_id'] ?? '') ?: null, trim($_POST['zabbix_hostid'] ?? '') ?: null, $by
    ) : false;
    echo json_encode(['success' => (bool)$ok]);
    exit;
}
if ($action === 'map_delete' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    $ok = $conn ? deleteHostImageMapping($conn, (int)($_POST['id'] ?? 0)) : false;
    echo json_encode(['success' => (bool)$ok]);
    exit;
}

// --- data ----------------------------------------------------------------
$zabbix = moriApiGet('/zabbix/hosts');
$risk   = moriApiGet('/vulnerabilities/risk-summary');
$moriBase = rtrim(getenv('MORI_API_URL') ?: 'http://host.docker.internal:18000', '/');

$hosts = $zabbix['hosts'] ?? [];
$riskItems = $risk['items'] ?? [];
$moriErr = $zabbix['_error'] ?? $risk['_error'] ?? null;

$byHost = [];
foreach ($riskItems as $it) {
    $h = $it['hostname'] ?? '';
    if (!isset($byHost[$h])) $byHost[$h] = ['total' => 0, 'levels' => []];
    $byHost[$h]['total']++;
    $lvl = $it['level'] ?? $it['severity'] ?? '?';
    $byHost[$h]['levels'][$lvl] = ($byHost[$h]['levels'][$lvl] ?? 0) + 1;
}

$images = $conn ? getScanHistoryByImage($conn) : [];
$mappings = $conn ? getHostImageMappings($conn) : [];
// hostname → [ {image, diff} ]
$hostImages = [];
foreach ($mappings as $m) {
    $sum = $conn ? getLatestDiffSummaryForImage($conn, $m['image_name']) : null;
    $hostImages[$m['hostname']][] = ['image' => $m['image_name'], 'map_id' => $m['id'], 'diff' => $sum];
}

function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES); }
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>CSOP Lab — Zabbix Host Context</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; color: #222; }
        .container { max-width: 1500px; margin: 0 auto; }
        h1, h2 { color: #333; }
        .lab-tag { display:inline-block; background:#6f42c1; color:#fff; font-size:11px; padding:2px 8px; border-radius:4px; vertical-align:middle; margin-left:8px; }
        .back-link { margin-bottom: 16px; }
        .back-link a { color:#007bff; text-decoration:none; margin-right:15px; }
        .flow { background:#ede7f6; border-left:4px solid #6f42c1; padding:10px 14px; border-radius:6px; font-size:13px; margin-bottom:16px; }
        .card { background:#fff; padding:20px; border-radius:8px; box-shadow:0 2px 4px rgba(0,0,0,0.08); margin-bottom:18px; }
        table { width:100%; border-collapse:collapse; font-size:13px; }
        th, td { padding:9px 10px; text-align:left; border-bottom:1px solid #eee; vertical-align:top; }
        th { background:#f8f9fa; }
        .imp-상 { color:#dc3545; font-weight:bold; } .imp-중 { color:#fd7e14; font-weight:bold; }
        .status-online { color:#198754; } .status-offline { color:#6c757d; }
        .pill { padding:2px 8px; border-radius:10px; font-size:11px; font-weight:bold; background:#e2e3e5; color:#41464b; }
        .risk-hi { background:#f8d7da; color:#842029; }
        .d-new { color:#842029; font-weight:bold; } .d-fixed { color:#0f5132; font-weight:bold; } .d-open { color:#664d03; font-weight:bold; }
        .err { background:#f8d7da; color:#842029; padding:12px; border-radius:6px; }
        .muted { color:#666; font-size:12px; }
        .btn { display:inline-block; padding:4px 9px; border-radius:4px; font-size:12px; text-decoration:none; background:#6f42c1; color:#fff; border:none; cursor:pointer; }
        .btn-sm { padding:2px 7px; font-size:11px; }
        .btn-del { background:#dc3545; }
        .imgline { padding:4px 0; border-bottom:1px dashed #eee; }
        code { background:#f0f0f0; padding:1px 5px; border-radius:3px; }
        select, input { padding:6px; border:1px solid #ccc; border-radius:4px; font-size:13px; }
        .maprow { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
    </style>
</head>
<body>
<div class="container">
    <div class="back-link">
        <a href="index.php">← 메인</a>
        <a href="csop_scan_diff.php">Scan Diff V2</a>
        <a href="csop_finding_lifecycle.php">Finding Lifecycle</a>
        <a href="?action=mappings" target="_blank">매핑 JSON</a>
    </div>
    <h1>🌐 Zabbix Host Context <span class="lab-tag">CSOP LAB</span></h1>
    <div class="flow">
        <b>Zabbix</b> host problem → <b>MORI</b> high-risk asset → <b>Trivy Agent</b> image scan →
        <b>CSOP</b> host↔image 매핑으로 자동 연결된 diff → <b>MORI</b> risk/evidence
    </div>

    <?php if ($moriErr): ?>
        <div class="err">MORI API 연결 실패: <?= h($moriErr) ?>
            <div class="muted">MORI_API_URL=<code><?= h($moriBase) ?></code></div>
        </div>
    <?php endif; ?>

    <div class="card">
        <h2>Zabbix Hosts <span class="muted">(MORI <code>/zabbix/hosts</code>, <?= count($hosts) ?>대) · 매핑된 이미지 diff 자동 표시</span></h2>
        <?php if (empty($hosts)): ?>
            <div class="muted">호스트가 없습니다.</div>
        <?php else: ?>
        <table>
            <thead><tr><th>Hostname</th><th>중요도</th><th>상태</th><th>CVE (MORI)</th><th>매핑된 Trivy 이미지 · 최신 diff</th></tr></thead>
            <tbody>
            <?php foreach ($hosts as $host):
                $hn = $host['hostname'] ?? '';
                $cve = $byHost[$hn] ?? null;
                $imgs = $hostImages[$hn] ?? []; ?>
                <tr>
                    <td><b><?= h($hn) ?></b><div class="muted"><?= h($host['primary_ip'] ?? '') ?></div></td>
                    <td class="imp-<?= h($host['importance'] ?? '') ?>"><?= h($host['importance'] ?? '-') ?></td>
                    <td class="status-<?= h($host['status'] ?? '') ?>"><?= h($host['status'] ?? '-') ?></td>
                    <td><?php if ($cve): ?><span class="pill risk-hi"><?= (int)$cve['total'] ?> CVE</span><?php else: ?><span class="muted">-</span><?php endif; ?></td>
                    <td>
                        <?php if (empty($imgs)): ?>
                            <span class="muted">매핑 없음 (아래에서 추가)</span>
                        <?php else: foreach ($imgs as $im): $d = $im['diff']; ?>
                            <div class="imgline">
                                <code><?= h($im['image']) ?></code>
                                <?php if ($d && $d['has_diff']): ?>
                                    <span class="d-new">New <?= (int)$d['new'] ?></span> ·
                                    <span class="d-fixed">Fixed <?= (int)$d['fixed'] ?></span> ·
                                    <span class="d-open">Still-open <?= (int)$d['still_open'] ?></span>
                                    <a class="btn btn-sm" href="csop_scan_diff.php">Diff →</a>
                                <?php elseif ($d): ?>
                                    <span class="muted">스캔 <?= (int)$d['still_open'] ?>건 (diff엔 2회 필요)</span>
                                <?php else: ?>
                                    <span class="muted">스캔 기록 없음</span>
                                <?php endif; ?>
                                <button class="btn btn-sm btn-del" onclick="delMap(<?= (int)$im['map_id'] ?>)">✕</button>
                            </div>
                        <?php endforeach; endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <?php endif; ?>
    </div>

    <div class="card">
        <h2>Host ↔ Image 매핑 추가</h2>
        <div class="maprow">
            <select id="m-host">
                <option value="">— Zabbix host 선택 —</option>
                <?php foreach ($hosts as $host): $hn = $host['hostname'] ?? ''; ?>
                    <option value="<?= h($hn) ?>" data-zid="<?= h($host['host_id'] ?? '') ?>"><?= h($hn) ?></option>
                <?php endforeach; ?>
            </select>
            <select id="m-image">
                <option value="">— Trivy 이미지 선택 —</option>
                <?php foreach ($images as $img): ?>
                    <option value="<?= h($img['image_name']) ?>"><?= h($img['image_name']) ?></option>
                <?php endforeach; ?>
            </select>
            <input id="m-agent" placeholder="agent_id (선택)" size="16">
            <button class="btn" onclick="addMap()">매핑 추가</button>
            <span id="m-msg" class="muted"></span>
        </div>
        <p class="muted" style="margin-top:10px;">
            매핑을 추가하면 위 표에서 해당 host에 이미지의 최신 diff가 자동 연결됩니다.
            매핑은 <code>?action=mappings</code> JSON으로도 노출되어 MORI가 host_id 파생 대신 소비할 수 있습니다.
        </p>
    </div>
</div>

<script>
    async function addMap() {
        const host = document.getElementById('m-host');
        const image = document.getElementById('m-image').value;
        const agent = document.getElementById('m-agent').value;
        const zid = host.selectedOptions[0]?.dataset.zid || '';
        if (!host.value || !image) { msg('host와 image를 선택하세요', true); return; }
        const body = new URLSearchParams({hostname: host.value, image_name: image, agent_id: agent, zabbix_hostid: zid});
        const r = await (await fetch('?action=map_add', {method:'POST', body})).json();
        if (r.success) location.reload(); else msg('실패', true);
    }
    async function delMap(id) {
        if (!confirm('매핑 삭제?')) return;
        const r = await (await fetch('?action=map_delete', {method:'POST', body: new URLSearchParams({id})})).json();
        if (r.success) location.reload();
    }
    function msg(t, err) { const e=document.getElementById('m-msg'); e.textContent=t; e.style.color=err?'#dc3545':'#198754'; }
</script>
</body>
</html>
