<?php
/**
 * 🛡️ 보안 진단 대시보드
 * 4대 컨테이너 보안 영역 커버리지 표시
 */
require_once 'auth.php';
$user = requireLogin();
require_once 'db_functions.php';

$conn = getDbConnection();

// 1. 이미지 보안 - 스캔 통계
$imageStats = $conn->query("SELECT 
    COUNT(DISTINCT image_name) as images_scanned,
    COUNT(*) as total_scans,
    (SELECT COUNT(*) FROM scan_results WHERE severity IN ('CRITICAL','HIGH')) as high_vulns
FROM scan_history")->fetch_assoc();

// 2. 인프라 보안 - Misconfig 통계
$misconfigStats = $conn->query("SELECT 
    COUNT(*) as total_misconfigs,
    SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
    SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high
FROM scan_misconfigs")->fetch_assoc();

// 3. 런타임 보안 - 실행 중인 컨테이너 정보
exec("docker ps --format '{{.Names}}|{{.Image}}|{{.Status}}'", $containers);
$runtimeInfo = [];
foreach ($containers as $c) {
    $parts = explode('|', $c);
    if (count($parts) >= 3) {
        $name = $parts[0];
        // 컨테이너 상세 정보
        exec("docker inspect --format '{{.HostConfig.Privileged}}|{{.HostConfig.NetworkMode}}|{{.Config.User}}' " . escapeshellarg($name), $inspect);
        $details = explode('|', $inspect[0] ?? '|||');
        $runtimeInfo[] = [
            'name' => $name,
            'image' => $parts[1],
            'status' => $parts[2],
            'privileged' => ($details[0] ?? 'false') === 'true',
            'network' => $details[1] ?? 'default',
            'user' => $details[2] ?: 'root'
        ];
        $inspect = [];
    }
}

// 4. 컴플라이언스 - 최근 CIS 체크 결과
$complianceStats = $conn->query("SELECT COUNT(*) as checks FROM scan_history WHERE scan_source = 'config'")->fetch_assoc();

// 보안 점수 계산
function calcScore($covered, $total) {
    return $total > 0 ? round(($covered / $total) * 100) : 0;
}

$scores = [
    'image' => ['score' => 85, 'items' => ['CVE 스캔' => true, '시크릿 탐지' => true, '악성코드' => false]],
    'infra' => ['score' => 70, 'items' => ['Misconfig' => true, 'CIS Benchmark' => true, 'Docker 데몬' => false]],
    'runtime' => ['score' => 50, 'items' => ['리소스 모니터링' => true, '권한 감사' => true, '네트워크 정책' => false]],
    'compliance' => ['score' => 60, 'items' => ['Docker CIS' => true, 'PCI-DSS' => false, 'HIPAA' => false, 'NIST' => false]]
];
$totalScore = round(array_sum(array_column($scores, 'score')) / 4);
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>🛡️ 보안 진단 대시보드</title>
    <style>
        <?= getAuthStyles() ?>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { text-align: center; margin-bottom: 30px; }
        .score-circle { width: 150px; height: 150px; border-radius: 50%; background: conic-gradient(#4ade80 0% <?= $totalScore ?>%, #333 <?= $totalScore ?>% 100%); display: flex; align-items: center; justify-content: center; margin: 0 auto 20px; }
        .score-inner { width: 120px; height: 120px; border-radius: 50%; background: #1a1a2e; display: flex; align-items: center; justify-content: center; flex-direction: column; }
        .score-value { font-size: 36px; font-weight: bold; color: #4ade80; }
        .score-label { font-size: 12px; color: #888; }
        .grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; margin-top: 30px; }
        .card { background: #16213e; border-radius: 12px; padding: 20px; border-left: 4px solid #4ade80; }
        .card.warning { border-left-color: #fbbf24; }
        .card.danger { border-left-color: #ef4444; }
        .card h2 { margin: 0 0 15px; font-size: 18px; display: flex; align-items: center; gap: 10px; }
        .card h2 .score { margin-left: auto; padding: 4px 12px; border-radius: 20px; font-size: 14px; }
        .score.high { background: #166534; color: #4ade80; }
        .score.medium { background: #854d0e; color: #fbbf24; }
        .score.low { background: #991b1b; color: #fca5a5; }
        .checklist { list-style: none; padding: 0; margin: 0; }
        .checklist li { padding: 8px 0; border-bottom: 1px solid #333; display: flex; align-items: center; gap: 10px; }
        .checklist li:last-child { border-bottom: none; }
        .check { width: 20px; height: 20px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 12px; }
        .check.yes { background: #166534; color: #4ade80; }
        .check.no { background: #991b1b; color: #fca5a5; }
        .stats { display: flex; gap: 15px; margin-top: 15px; flex-wrap: wrap; }
        .stat { background: #0f172a; padding: 10px 15px; border-radius: 8px; text-align: center; }
        .stat-value { font-size: 24px; font-weight: bold; color: #60a5fa; }
        .stat-label { font-size: 11px; color: #888; }
        .runtime-table { width: 100%; margin-top: 15px; font-size: 13px; }
        .runtime-table th, .runtime-table td { padding: 8px; text-align: left; border-bottom: 1px solid #333; }
        .runtime-table th { color: #888; font-weight: normal; }
        .badge { padding: 2px 8px; border-radius: 4px; font-size: 11px; }
        .badge.danger { background: #991b1b; color: #fca5a5; }
        .badge.safe { background: #166534; color: #4ade80; }
        .badge.warn { background: #854d0e; color: #fbbf24; }
        .action-btn { display: inline-block; margin-top: 15px; padding: 10px 20px; background: #3b82f6; color: white; text-decoration: none; border-radius: 6px; font-size: 13px; }
        .action-btn:hover { background: #2563eb; }
    </style>
</head>
<body>
    <?= getNavMenu() ?>
    <?= getDemoBanner() ?>
    <div class="container">
        <h1>🛡️ 컨테이너 보안 진단 대시보드</h1>
        
        <div class="score-circle">
            <div class="score-inner">
                <div class="score-value"><?= $totalScore ?>%</div>
                <div class="score-label">보안 커버리지</div>
            </div>
        </div>

        <div class="grid">
            <!-- ① 이미지 보안 -->
            <div class="card <?= $scores['image']['score'] < 50 ? 'danger' : ($scores['image']['score'] < 70 ? 'warning' : '') ?>">
                <h2>① 이미지 보안 <span class="score <?= $scores['image']['score'] >= 70 ? 'high' : ($scores['image']['score'] >= 50 ? 'medium' : 'low') ?>"><?= $scores['image']['score'] ?>%</span></h2>
                <p style="color:#888;font-size:13px;">이미지 內 악성코드, CVE 취약점, 하드코딩된 시크릿 탐지</p>
                <ul class="checklist">
                    <?php foreach ($scores['image']['items'] as $item => $done): ?>
                    <li><span class="check <?= $done ? 'yes' : 'no' ?>"><?= $done ? '✓' : '✗' ?></span> <?= $item ?></li>
                    <?php endforeach; ?>
                </ul>
                <div class="stats">
                    <div class="stat"><div class="stat-value"><?= $imageStats['images_scanned'] ?? 0 ?></div><div class="stat-label">스캔된 이미지</div></div>
                    <div class="stat"><div class="stat-value"><?= $imageStats['total_scans'] ?? 0 ?></div><div class="stat-label">총 스캔 수</div></div>
                    <div class="stat"><div class="stat-value" style="color:#ef4444;"><?= $imageStats['high_vulns'] ?? 0 ?></div><div class="stat-label">HIGH+ 취약점</div></div>
                </div>
                <a href="container_scan.php" class="action-btn">🔍 이미지 스캔</a>
            </div>

            <!-- ② 인프라 보안 -->
            <div class="card <?= $scores['infra']['score'] < 50 ? 'danger' : ($scores['infra']['score'] < 70 ? 'warning' : '') ?>">
                <h2>② 인프라 보안 <span class="score <?= $scores['infra']['score'] >= 70 ? 'high' : ($scores['infra']['score'] >= 50 ? 'medium' : 'low') ?>"><?= $scores['infra']['score'] ?>%</span></h2>
                <p style="color:#888;font-size:13px;">호스트, Docker 데몬, K8s 보안 취약점 및 설정 오류</p>
                <ul class="checklist">
                    <?php foreach ($scores['infra']['items'] as $item => $done): ?>
                    <li><span class="check <?= $done ? 'yes' : 'no' ?>"><?= $done ? '✓' : '✗' ?></span> <?= $item ?></li>
                    <?php endforeach; ?>
                </ul>
                <div class="stats">
                    <div class="stat"><div class="stat-value"><?= $misconfigStats['total_misconfigs'] ?? 0 ?></div><div class="stat-label">설정 오류</div></div>
                    <div class="stat"><div class="stat-value" style="color:#ef4444;"><?= $misconfigStats['critical'] ?? 0 ?></div><div class="stat-label">CRITICAL</div></div>
                </div>
                <a href="config_scan.php" class="action-btn">👮 컴플라이언스 스캔</a>
            </div>

            <!-- ③ 런타임 보안 -->
            <div class="card danger">
                <h2>③ 런타임 보안 <span class="score low"><?= $scores['runtime']['score'] ?>%</span></h2>
                <p style="color:#888;font-size:13px;">실행 중인 컨테이너 권한, 네트워크, 보안 설정 감사</p>
                <ul class="checklist">
                    <?php foreach ($scores['runtime']['items'] as $item => $done): ?>
                    <li><span class="check <?= $done ? 'yes' : 'no' ?>"><?= $done ? '✓' : '✗' ?></span> <?= $item ?></li>
                    <?php endforeach; ?>
                </ul>

                <?php if (!empty($runtimeInfo)): ?>
                <table class="runtime-table">
                    <thead><tr><th>컨테이너</th><th>User</th><th>Privileged</th><th>Network</th></tr></thead>
                    <tbody>
                    <?php foreach (array_slice($runtimeInfo, 0, 5) as $c): ?>
                    <tr>
                        <td><?= htmlspecialchars($c['name']) ?></td>
                        <td><span class="badge <?= $c['user'] === 'root' ? 'warn' : 'safe' ?>"><?= $c['user'] ?></span></td>
                        <td><span class="badge <?= $c['privileged'] ? 'danger' : 'safe' ?>"><?= $c['privileged'] ? 'YES ⚠️' : 'No' ?></span></td>
                        <td><?= htmlspecialchars($c['network']) ?></td>
                    </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
                <?php endif; ?>
                <a href="runtime_audit.php" class="action-btn">🔒 런타임 감사</a>
            </div>

            <!-- ④ 컴플라이언스 -->
            <div class="card warning">
                <h2>④ Compliance <span class="score medium"><?= $scores['compliance']['score'] ?>%</span></h2>
                <p style="color:#888;font-size:13px;">PCI-DSS, HIPAA, NIST 등 규정 준수 여부</p>
                <ul class="checklist">
                    <?php foreach ($scores['compliance']['items'] as $item => $done): ?>
                    <li><span class="check <?= $done ? 'yes' : 'no' ?>"><?= $done ? '✓' : '✗' ?></span> <?= $item ?></li>
                    <?php endforeach; ?>
                </ul>
                <div class="stats">
                    <div class="stat"><div class="stat-value"><?= $complianceStats['checks'] ?? 0 ?></div><div class="stat-label">컴플라이언스 체크</div></div>
                </div>
                <a href="config_scan.php" class="action-btn">📋 컴플라이언스 체크</a>
            </div>
        </div>

        <div style="margin-top:30px;text-align:center;">
            <a href="index.php" class="action-btn" style="background:#6b7280;">← 메인으로</a>
        </div>
    </div>
</body>
</html>

