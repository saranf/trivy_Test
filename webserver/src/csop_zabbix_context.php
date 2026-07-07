<?php
/**
 * CSOP Lab — Zabbix Host Context
 *
 * Correlates MORI-SOC's Zabbix hosts with vulnerability risk and CSOP Trivy
 * scan diffs. This is the "Zabbix → Trivy → MORI" story on one screen:
 * a host problem in Zabbix + that host's CVE risk + a link into the CSOP diff.
 *
 * Reads MORI live (server-side): GET /zabbix/hosts, GET /vulnerabilities/risk-summary.
 * See docs/MORI_INTEGRATION.md.
 */
require_once 'db_functions.php';

$conn = getDbConnection();
if ($conn) { initDatabase($conn); }

$zabbix = moriApiGet('/zabbix/hosts');
$risk   = moriApiGet('/vulnerabilities/risk-summary');
$moriBase = rtrim(getenv('MORI_API_URL') ?: 'http://host.docker.internal:18000', '/');

$hosts = $zabbix['hosts'] ?? [];
$riskItems = $risk['items'] ?? [];

// CVE 리스크를 hostname 기준으로 묶기
$byHost = [];
foreach ($riskItems as $it) {
    $h = $it['hostname'] ?? '';
    if (!isset($byHost[$h])) $byHost[$h] = ['total' => 0, 'levels' => []];
    $byHost[$h]['total']++;
    $lvl = $it['level'] ?? $it['severity'] ?? '?';
    $byHost[$h]['levels'][$lvl] = ($byHost[$h]['levels'][$lvl] ?? 0) + 1;
}

$images = $conn ? getScanHistoryByImage($conn) : [];
$moriErr = $zabbix['_error'] ?? $risk['_error'] ?? null;

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
        th, td { padding:9px 10px; text-align:left; border-bottom:1px solid #eee; }
        th { background:#f8f9fa; }
        .imp-상, .imp-high { color:#dc3545; font-weight:bold; }
        .imp-중, .imp-medium { color:#fd7e14; font-weight:bold; }
        .status-online { color:#198754; } .status-offline { color:#6c757d; }
        .pill { padding:2px 8px; border-radius:10px; font-size:11px; font-weight:bold; background:#e2e3e5; color:#41464b; }
        .risk-hi { background:#f8d7da; color:#842029; }
        .risk-mid { background:#fff3cd; color:#664d03; }
        .err { background:#f8d7da; color:#842029; padding:12px; border-radius:6px; }
        .muted { color:#666; font-size:12px; }
        .btn { display:inline-block; padding:5px 10px; border-radius:4px; font-size:12px; text-decoration:none; background:#6f42c1; color:#fff; }
        code { background:#f0f0f0; padding:1px 5px; border-radius:3px; }
    </style>
</head>
<body>
<div class="container">
    <div class="back-link">
        <a href="index.php">← 메인</a>
        <a href="csop_scan_diff.php">Scan Diff V2</a>
        <a href="csop_finding_lifecycle.php">Finding Lifecycle</a>
    </div>
    <h1>🌐 Zabbix Host Context <span class="lab-tag">CSOP LAB</span></h1>
    <div class="flow">
        <b>Zabbix</b> host problem → <b>MORI</b> high-risk asset → <b>Trivy Agent</b> image scan →
        <b>CSOP</b> scan diff → <b>MORI</b> risk/evidence
    </div>

    <?php if ($moriErr): ?>
        <div class="err">MORI API 연결 실패: <?= h($moriErr) ?><br>
            <span class="muted">MORI_API_URL=<code><?= h($moriBase) ?></code> — MORI가 떠 있는지, webserver에서 접근 가능한지 확인하세요.</span>
        </div>
    <?php endif; ?>

    <div class="card">
        <h2>Zabbix Hosts <span class="muted">(MORI <code>/zabbix/hosts</code>, <?= count($hosts) ?>대)</span></h2>
        <?php if (empty($hosts)): ?>
            <div class="muted">호스트가 없습니다.</div>
        <?php else: ?>
        <table>
            <thead><tr><th>Hostname</th><th>분류</th><th>중요도</th><th>상태</th><th>Zabbix Risk</th><th>CVE 리스크 (MORI)</th><th>최근 메트릭</th></tr></thead>
            <tbody>
            <?php foreach ($hosts as $host):
                $hn = $host['hostname'] ?? '';
                $cve = $byHost[$hn] ?? null; ?>
                <tr>
                    <td><b><?= h($hn) ?></b><div class="muted"><?= h($host['primary_ip'] ?? '') ?></div></td>
                    <td><?= h($host['category'] ?? $host['asset_type'] ?? '-') ?></td>
                    <td class="imp-<?= h($host['importance'] ?? '') ?>"><?= h($host['importance'] ?? '-') ?></td>
                    <td class="status-<?= h($host['status'] ?? '') ?>"><?= h($host['status'] ?? '-') ?></td>
                    <td><?= h($host['risk_score'] ?? '-') ?></td>
                    <td>
                        <?php if ($cve): ?>
                            <span class="pill risk-hi"><?= (int)$cve['total'] ?> CVE</span>
                            <?php foreach ($cve['levels'] as $lvl => $n): ?>
                                <span class="pill"><?= h($lvl) ?>:<?= (int)$n ?></span>
                            <?php endforeach; ?>
                        <?php else: ?><span class="muted">해당 host CVE 없음</span><?php endif; ?>
                    </td>
                    <td class="muted"><?= h($host['latest_metric'] ?? '-') ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <?php endif; ?>
    </div>

    <div class="card">
        <h2>CSOP Trivy 스캔 이미지 <span class="muted">(diff로 조치 전/후 확인)</span></h2>
        <?php if (empty($images)): ?>
            <div class="muted">CSOP에 스캔 기록이 없습니다. 컨테이너 스캔 후 diff를 볼 수 있습니다.</div>
        <?php else: ?>
        <table>
            <thead><tr><th>이미지</th><th>스캔 횟수</th><th>마지막</th><th></th></tr></thead>
            <tbody>
            <?php foreach ($images as $img): ?>
                <tr>
                    <td><b><?= h($img['image_name']) ?></b></td>
                    <td><?= (int)$img['scan_count'] ?></td>
                    <td class="muted"><?= h($img['last_scan']) ?></td>
                    <td>
                        <a class="btn" href="csop_scan_diff.php">Scan Diff →</a>
                        <a class="btn" href="csop_finding_lifecycle.php">Lifecycle →</a>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <?php endif; ?>
        <p class="muted" style="margin-top:12px;">
            상관 규칙(다음 단계): Zabbix host ↔ Trivy 이미지 매핑을 붙이면 host 문제 발생 시 해당
            이미지의 diff를 자동으로 연결할 수 있습니다. 현재는 두 소스를 한 화면에서 대조합니다.
        </p>
    </div>
</div>
</body>
</html>
