<?php
/**
 * 🔒 런타임 보안 감사
 * 실행 중인 컨테이너의 보안 설정 점검
 */
require_once 'auth.php';
$user = requireRole('operator');

// 컨테이너 정보 수집
function getContainerSecurityInfo() {
    $containers = [];
    exec("docker ps --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}'", $output);
    
    foreach ($output as $line) {
        $parts = explode('|', $line);
        if (count($parts) < 4) continue;
        
        $id = $parts[0];
        $name = $parts[1];
        
        // 상세 보안 정보 조회
        $inspectCmd = "docker inspect --format '" .
            "{{.HostConfig.Privileged}}|" .
            "{{.HostConfig.NetworkMode}}|" .
            "{{.Config.User}}|" .
            "{{.HostConfig.ReadonlyRootfs}}|" .
            "{{.HostConfig.CapAdd}}|" .
            "{{.HostConfig.CapDrop}}|" .
            "{{.HostConfig.SecurityOpt}}|" .
            "{{.HostConfig.PidMode}}|" .
            "{{range .Mounts}}{{.Type}}:{{.Source}}:{{.Destination}}:{{.RW}},{{end}}' " . escapeshellarg($id);
        
        exec($inspectCmd, $inspect);
        $details = explode('|', $inspect[0] ?? '');
        
        $mounts = [];
        if (!empty($details[8])) {
            foreach (explode(',', trim($details[8], ',')) as $m) {
                $mp = explode(':', $m);
                if (count($mp) >= 4) {
                    $mounts[] = ['type' => $mp[0], 'src' => $mp[1], 'dst' => $mp[2], 'rw' => $mp[3] === 'true'];
                }
            }
        }
        
        $containers[] = [
            'id' => $id,
            'name' => $name,
            'image' => $parts[2],
            'status' => $parts[3],
            'privileged' => ($details[0] ?? 'false') === 'true',
            'network' => $details[1] ?? 'default',
            'user' => $details[2] ?: 'root',
            'readonly_rootfs' => ($details[3] ?? 'false') === 'true',
            'cap_add' => $details[4] ?? '[]',
            'cap_drop' => $details[5] ?? '[]',
            'security_opt' => $details[6] ?? '[]',
            'pid_mode' => $details[7] ?? '',
            'mounts' => $mounts
        ];
        $inspect = [];
    }
    return $containers;
}

// 보안 점수 계산
function calcSecurityScore($c) {
    $score = 100;
    $issues = [];
    
    if ($c['privileged']) { $score -= 40; $issues[] = ['🔴 CRITICAL', 'Privileged 모드 활성화']; }
    if ($c['user'] === 'root') { $score -= 15; $issues[] = ['🟠 HIGH', 'root 사용자로 실행']; }
    if (!$c['readonly_rootfs']) { $score -= 10; $issues[] = ['🟡 MEDIUM', '루트 파일시스템 쓰기 가능']; }
    if ($c['pid_mode'] === 'host') { $score -= 20; $issues[] = ['🔴 CRITICAL', 'Host PID 네임스페이스 공유']; }
    if ($c['network'] === 'host') { $score -= 15; $issues[] = ['🟠 HIGH', 'Host 네트워크 모드']; }
    if (strpos($c['cap_add'], 'SYS_ADMIN') !== false) { $score -= 25; $issues[] = ['🔴 CRITICAL', 'SYS_ADMIN capability 추가됨']; }
    
    foreach ($c['mounts'] as $m) {
        if ($m['type'] === 'bind' && strpos($m['src'], '/var/run/docker.sock') !== false) {
            $score -= 30; $issues[] = ['🔴 CRITICAL', 'Docker 소켓 마운트됨'];
        }
        if ($m['type'] === 'bind' && $m['src'] === '/' && $m['rw']) {
            $score -= 35; $issues[] = ['🔴 CRITICAL', '호스트 루트(/) 쓰기 마운트'];
        }
    }
    
    return ['score' => max(0, $score), 'issues' => $issues];
}

$containers = getContainerSecurityInfo();
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>🔒 런타임 보안 감사</title>
    <style>
        <?= getAuthStyles() ?>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { color: #333; }
        .info-box { background: linear-gradient(135deg, #ef4444 0%, #b91c1c 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(400px, 1fr)); gap: 20px; }
        .card { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .card-header { display: flex; align-items: center; gap: 10px; margin-bottom: 15px; padding-bottom: 15px; border-bottom: 1px solid #eee; }
        .card-header h3 { margin: 0; flex: 1; font-size: 16px; }
        .score-badge { padding: 6px 14px; border-radius: 20px; font-weight: bold; font-size: 14px; }
        .score-high { background: #dcfce7; color: #166534; }
        .score-medium { background: #fef3c7; color: #92400e; }
        .score-low { background: #fee2e2; color: #991b1b; }
        .meta { font-size: 12px; color: #888; margin-bottom: 10px; }
        .issues { list-style: none; padding: 0; margin: 0; }
        .issues li { padding: 8px; margin: 5px 0; background: #fef2f2; border-radius: 4px; font-size: 13px; border-left: 3px solid #ef4444; }
        .issues li.warn { background: #fffbeb; border-left-color: #f59e0b; }
        .issues li.info { background: #eff6ff; border-left-color: #3b82f6; }
        .no-issues { color: #166534; background: #dcfce7; padding: 15px; border-radius: 4px; text-align: center; }
        .detail-table { width: 100%; font-size: 12px; margin-top: 10px; }
        .detail-table td { padding: 4px 0; }
        .detail-table td:first-child { color: #888; width: 120px; }
        .badge { padding: 2px 8px; border-radius: 4px; font-size: 11px; }
        .badge.danger { background: #fee2e2; color: #991b1b; }
        .badge.safe { background: #dcfce7; color: #166534; }
        .badge.warn { background: #fef3c7; color: #92400e; }
        a.btn { display: inline-block; padding: 10px 20px; background: #3b82f6; color: white; text-decoration: none; border-radius: 6px; margin-top: 20px; }
        .search-box { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .search-box h3 { margin: 0 0 15px; font-size: 16px; }
        .search-row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
        .search-row select, .search-row input { padding: 10px 15px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; }
        .search-row select { min-width: 250px; }
        .search-row button { padding: 10px 20px; background: #3b82f6; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; }
        .search-row button:hover { background: #2563eb; }
        .search-row .btn-reset { background: #6b7280; }
        .search-row .btn-reset:hover { background: #4b5563; }
        .stats-bar { display: flex; gap: 20px; margin-bottom: 20px; flex-wrap: wrap; }
        .stat-item { background: white; padding: 15px 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .stat-item .label { font-size: 12px; color: #888; }
        .stat-item .value { font-size: 24px; font-weight: bold; }
        .stat-item .value.good { color: #166534; }
        .stat-item .value.bad { color: #991b1b; }
        .card.hidden { display: none; }
    </style>
</head>
<body>
    <?= getNavMenu() ?>
    <?= getDemoBanner() ?>
    <div class="container">
        <h1>🔒 런타임 보안 감사</h1>

        <div class="info-box">
            <h2 style="margin:0 0 10px;">③ 런타임 보안 이슈</h2>
            <p style="margin:0;">실행 중인 컨테이너의 <strong>권한 설정</strong>, <strong>네트워크 모드</strong>, <strong>마운트</strong> 등을 점검합니다.</p>
        </div>

        <!-- 검색/필터 영역 -->
        <div class="search-box">
            <h3>🔍 컨테이너 검색</h3>
            <div class="search-row">
                <select id="containerSelect">
                    <option value="">-- 모든 컨테이너 보기 --</option>
                    <?php foreach ($containers as $c): ?>
                    <option value="<?= htmlspecialchars($c['name']) ?>"><?= htmlspecialchars($c['name']) ?> (<?= htmlspecialchars($c['image']) ?>)</option>
                    <?php endforeach; ?>
                </select>
                <input type="text" id="searchInput" placeholder="컨테이너명 또는 이미지명 검색..." style="flex:1; min-width:200px;">
                <button onclick="filterContainers()">🔍 검색</button>
                <button class="btn-reset" onclick="resetFilter()">초기화</button>
            </div>
        </div>

        <!-- 통계 -->
        <div class="stats-bar">
            <div class="stat-item">
                <div class="label">전체 컨테이너</div>
                <div class="value"><?= count($containers) ?>개</div>
            </div>
            <div class="stat-item">
                <div class="label">보안 이슈 없음</div>
                <div class="value good" id="safeCount">0개</div>
            </div>
            <div class="stat-item">
                <div class="label">보안 이슈 있음</div>
                <div class="value bad" id="issueCount">0개</div>
            </div>
            <div class="stat-item">
                <div class="label">평균 보안 점수</div>
                <div class="value" id="avgScore">0점</div>
            </div>
        </div>

        <div class="grid" id="containerGrid">
            <?php
            $safeCount = 0;
            $issueCount = 0;
            $totalScore = 0;
            foreach ($containers as $c):
                $sec = calcSecurityScore($c);
                $scoreClass = $sec['score'] >= 80 ? 'high' : ($sec['score'] >= 50 ? 'medium' : 'low');
                $totalScore += $sec['score'];
                if (empty($sec['issues'])) $safeCount++; else $issueCount++;
            ?>
            <div class="card" data-name="<?= htmlspecialchars(strtolower($c['name'])) ?>" data-image="<?= htmlspecialchars(strtolower($c['image'])) ?>">
                <div class="card-header">
                    <h3>🐳 <?= htmlspecialchars($c['name']) ?></h3>
                    <span class="score-badge score-<?= $scoreClass ?>"><?= $sec['score'] ?>점</span>
                </div>
                <div class="meta">
                    📦 <?= htmlspecialchars($c['image']) ?><br>
                    🔄 <?= htmlspecialchars($c['status']) ?>
                </div>

                <?php if (empty($sec['issues'])): ?>
                <div class="no-issues">✅ 보안 이슈 없음</div>
                <?php else: ?>
                <ul class="issues">
                    <?php foreach ($sec['issues'] as $issue): ?>
                    <li class="<?= strpos($issue[0], 'MEDIUM') !== false ? 'warn' : '' ?>"><?= $issue[0] ?> <?= $issue[1] ?></li>
                    <?php endforeach; ?>
                </ul>
                <?php endif; ?>
            </div>
            <?php endforeach; ?>
        </div>

        <a href="security_dashboard.php" class="btn">← 보안 대시보드</a>
    </div>

    <script>
        // 초기 통계 업데이트
        document.getElementById('safeCount').textContent = '<?= $safeCount ?>개';
        document.getElementById('issueCount').textContent = '<?= $issueCount ?>개';
        document.getElementById('avgScore').textContent = '<?= count($containers) > 0 ? round($totalScore / count($containers)) : 0 ?>점';

        function filterContainers() {
            const select = document.getElementById('containerSelect').value.toLowerCase();
            const search = document.getElementById('searchInput').value.toLowerCase();
            const cards = document.querySelectorAll('.card');

            cards.forEach(card => {
                const name = card.dataset.name;
                const image = card.dataset.image;

                let show = true;

                // 드롭다운 선택 시
                if (select && name !== select) {
                    show = false;
                }

                // 텍스트 검색
                if (search && !name.includes(search) && !image.includes(search)) {
                    show = false;
                }

                card.classList.toggle('hidden', !show);
            });
        }

        function resetFilter() {
            document.getElementById('containerSelect').value = '';
            document.getElementById('searchInput').value = '';
            document.querySelectorAll('.card').forEach(card => card.classList.remove('hidden'));
        }

        // 드롭다운 변경 시 자동 필터링
        document.getElementById('containerSelect').addEventListener('change', filterContainers);

        // Enter 키로 검색
        document.getElementById('searchInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') filterContainers();
        });
    </script>
</body>
</html>

