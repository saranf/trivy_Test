<?php
/**
 * 🤖 에이전트 관리 페이지
 * - 등록된 에이전트 목록
 * - 에이전트 상태 모니터링
 * - 자산 그룹/태그 관리
 * - 명령 전송
 * - 수집된 데이터 조회
 */
require_once 'auth.php';
require_once 'db_functions.php';

requireAuth();
if (!isOperator()) {
    header('Location: index.php');
    exit;
}

$conn = getDbConnection();
initDatabase($conn);

// 오프라인 에이전트 마킹
markOfflineAgents($conn);

$user = getCurrentUser();

// 필터 파라미터
$filterGroup = isset($_GET['group']) ? (int)$_GET['group'] : null;
$filterTag = isset($_GET['tag']) ? (int)$_GET['tag'] : null;
$filterStatus = isset($_GET['status']) ? $_GET['status'] : null;

// 그룹/태그 목록 조회
$assetGroups = getAssetGroups($conn);
$assetTags = getAssetTags($conn);

// 필터링된 에이전트 조회
if ($filterGroup || $filterTag || $filterStatus) {
    $tagIds = $filterTag ? [$filterTag] : [];
    $agents = getAgentsByFilter($conn, $filterGroup, $tagIds, $filterStatus);
} else {
    $agents = getAgents($conn);
}

// 각 에이전트별 통계 및 태그 추가
foreach ($agents as &$agent) {
    // 스캔 통계
    $stmt = $conn->prepare("
        SELECT COUNT(*) as scan_count,
               COALESCE(SUM(critical_count), 0) as total_critical,
               COALESCE(SUM(high_count), 0) as total_high
        FROM scan_history
        WHERE agent_id = ? AND scan_date > DATE_SUB(NOW(), INTERVAL 24 HOUR)
    ");
    $stmt->bind_param("s", $agent['agent_id']);
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();
    $agent['recent_scans'] = $result['scan_count'] ?? 0;
    $agent['recent_critical'] = $result['total_critical'] ?? 0;
    $agent['recent_high'] = $result['total_high'] ?? 0;
    $stmt->close();

    // 그룹/태그 정보
    $agent['groups'] = getAgentGroups($conn, $agent['agent_id']);
    $agent['tags'] = getAgentTags($conn, $agent['agent_id']);
}
unset($agent);

// 그룹별 통계 계산
$groupStats = [];
foreach ($assetGroups as $group) {
    $groupStats[$group['id']] = getVulnStatsByGroup($conn, $group['id']);
}

$conn->close();
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🤖 에이전트 관리 - Trivy Scanner</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #0f0f1a; color: #e0e0e0; min-height: 100vh; }
        <?= getAuthStyles() ?>
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        h1 { margin-bottom: 20px; }
        .stats-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .stat-card { background: linear-gradient(135deg, #1a1a2e, #16213e); padding: 20px; border-radius: 10px; text-align: center; }
        .stat-card .number { font-size: 2.5em; font-weight: bold; }
        .stat-card .label { color: #888; font-size: 0.9em; margin-top: 5px; }
        .stat-card.online .number { color: #27ae60; }
        .stat-card.offline .number { color: #e74c3c; }
        .stat-card.total .number { color: #3498db; }
        
        .card { background: #1a1a2e; border-radius: 10px; padding: 20px; margin-bottom: 20px; }
        .card h2 { margin-bottom: 15px; display: flex; align-items: center; gap: 10px; }
        
        .agents-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 20px; }
        .agent-card { background: linear-gradient(135deg, #16213e, #1a1a2e); border-radius: 10px; padding: 20px; border-left: 4px solid #3498db; }
        .agent-card.online { border-left-color: #27ae60; }
        .agent-card.offline { border-left-color: #e74c3c; }
        .agent-card.error { border-left-color: #f39c12; }
        
        .agent-header { display: flex; justify-content: space-between; align-items: start; margin-bottom: 15px; }
        .agent-name { font-size: 1.2em; font-weight: bold; }
        .agent-status { padding: 4px 10px; border-radius: 15px; font-size: 0.8em; font-weight: bold; }
        .agent-status.online { background: #27ae60; color: white; }
        .agent-status.offline { background: #e74c3c; color: white; }
        .agent-status.error { background: #f39c12; color: white; }
        
        .agent-info { font-size: 0.9em; color: #888; margin-bottom: 10px; }
        .agent-info div { margin: 5px 0; }
        .agent-stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin: 15px 0; }
        .agent-stat { text-align: center; padding: 10px; background: rgba(0,0,0,0.2); border-radius: 5px; }
        .agent-stat .value { font-size: 1.5em; font-weight: bold; }
        .agent-stat .label { font-size: 0.75em; color: #888; }
        .agent-stat.critical .value { color: #e74c3c; }
        .agent-stat.high .value { color: #f39c12; }
        
        .agent-actions { display: flex; gap: 10px; flex-wrap: wrap; }
        .btn { padding: 8px 15px; border: none; border-radius: 5px; cursor: pointer; font-size: 0.85em; text-decoration: none; display: inline-flex; align-items: center; gap: 5px; }
        .btn-primary { background: #3498db; color: white; }
        .btn-success { background: #27ae60; color: white; }
        .btn-warning { background: #f39c12; color: white; }
        .btn-danger { background: #e74c3c; color: white; }
        .btn:hover { opacity: 0.9; }
        
        .empty-state { text-align: center; padding: 60px 20px; color: #666; }
        .empty-state h3 { margin-bottom: 10px; font-size: 1.5em; }
        .install-code { background: #0d0d1a; padding: 20px; border-radius: 8px; margin-top: 20px; text-align: left; overflow-x: auto; }
        .install-code code { color: #27ae60; font-family: monospace; white-space: pre-wrap; }

        /* Tabs */
        .tabs { display: flex; gap: 5px; margin-bottom: 20px; flex-wrap: wrap; }
        .tab { padding: 10px 20px; background: #16213e; border: none; color: #888; border-radius: 5px 5px 0 0; cursor: pointer; }
        .tab.active { background: #1a1a2e; color: white; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }

        /* Filter bar */
        .filter-bar { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; align-items: center; }
        .filter-bar select { padding: 8px 15px; background: #16213e; border: 1px solid #333; color: white; border-radius: 5px; }
        .filter-bar .filter-label { color: #888; }

        /* Tags */
        .tag { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 0.75em; margin: 2px; }
        .tag-group { background: #3498db; color: white; }
        .agent-tags { margin: 10px 0; display: flex; flex-wrap: wrap; gap: 5px; }

        /* Group cards */
        .groups-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .group-card { background: linear-gradient(135deg, #16213e, #1a1a2e); border-radius: 10px; padding: 15px; cursor: pointer; transition: transform 0.2s; }
        .group-card:hover { transform: translateY(-3px); }
        .group-card.active { border: 2px solid #3498db; }
        .group-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .group-name { font-size: 1.1em; font-weight: bold; }
        .group-count { background: rgba(255,255,255,0.1); padding: 2px 8px; border-radius: 10px; font-size: 0.8em; }
        .group-stats { display: flex; gap: 15px; font-size: 0.85em; }
        .group-stats span { display: flex; align-items: center; gap: 5px; }
        .group-stats .critical { color: #e74c3c; }
        .group-stats .high { color: #f39c12; }

        /* Modal */
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 1000; align-items: center; justify-content: center; }
        .modal.active { display: flex; }
        .modal-content { background: #1a1a2e; border-radius: 10px; padding: 30px; max-width: 800px; width: 90%; max-height: 80vh; overflow-y: auto; }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .modal-close { background: none; border: none; color: white; font-size: 1.5em; cursor: pointer; }

        /* Tag management */
        .tag-section { margin: 15px 0; }
        .tag-section h4 { margin-bottom: 10px; color: #888; font-size: 0.9em; }
        .tag-list { display: flex; flex-wrap: wrap; gap: 5px; }
        .tag-toggle { cursor: pointer; opacity: 0.5; transition: opacity 0.2s; }
        .tag-toggle.active { opacity: 1; }
        .tag-toggle:hover { opacity: 0.8; }
    </style>
</head>
<body>
    <?= getNavMenu() ?>
    <div class="container">
        <h1>🤖 에이전트 & 자산 관리</h1>

        <!-- 탭 메뉴 -->
        <div class="tabs">
            <button class="tab active" onclick="showTab('agents')">🖥️ 에이전트</button>
            <button class="tab" onclick="showTab('groups')">📁 자산 그룹</button>
            <button class="tab" onclick="showTab('tags')">🏷️ 태그 관리</button>
        </div>

        <?php
        $onlineCount = count(array_filter($agents, fn($a) => $a['status'] === 'online'));
        $offlineCount = count(array_filter($agents, fn($a) => $a['status'] === 'offline'));
        ?>

        <!-- 에이전트 탭 -->
        <div id="tab-agents" class="tab-content active">
            <div class="stats-row">
                <div class="stat-card total">
                    <div class="number"><?= count($agents) ?></div>
                    <div class="label">전체 에이전트</div>
                </div>
                <div class="stat-card online">
                    <div class="number"><?= $onlineCount ?></div>
                    <div class="label">온라인</div>
                </div>
                <div class="stat-card offline">
                    <div class="number"><?= $offlineCount ?></div>
                    <div class="label">오프라인</div>
                </div>
            </div>

            <!-- 필터 바 -->
            <div class="filter-bar">
                <span class="filter-label">필터:</span>
                <select onchange="applyFilter('group', this.value)">
                    <option value="">모든 그룹</option>
                    <?php foreach ($assetGroups as $group): ?>
                    <option value="<?= $group['id'] ?>" <?= $filterGroup == $group['id'] ? 'selected' : '' ?>>
                        <?= htmlspecialchars($group['icon'] . ' ' . $group['display_name']) ?>
                    </option>
                    <?php endforeach; ?>
                </select>
                <select onchange="applyFilter('tag', this.value)">
                    <option value="">모든 태그</option>
                    <?php foreach ($assetTags as $tag): ?>
                    <option value="<?= $tag['id'] ?>" <?= $filterTag == $tag['id'] ? 'selected' : '' ?>>
                        <?= htmlspecialchars($tag['display_name']) ?>
                    </option>
                    <?php endforeach; ?>
                </select>
                <select onchange="applyFilter('status', this.value)">
                    <option value="">모든 상태</option>
                    <option value="online" <?= $filterStatus === 'online' ? 'selected' : '' ?>>🟢 온라인</option>
                    <option value="offline" <?= $filterStatus === 'offline' ? 'selected' : '' ?>>🔴 오프라인</option>
                </select>
                <?php if ($filterGroup || $filterTag || $filterStatus): ?>
                <a href="agents.php" class="btn btn-warning">필터 초기화</a>
                <?php endif; ?>
            </div>

            <?php if (empty($agents) && !$filterGroup && !$filterTag && !$filterStatus): ?>
        <div class="card">
            <div class="empty-state">
                <h3>🤖 등록된 에이전트가 없습니다</h3>
                <p>아래 명령어로 서버에 에이전트를 설치하세요.</p>
                <div class="install-code">
                    <code># Docker로 설치
docker run -d --name trivy-agent \
  --restart unless-stopped \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e CENTRAL_API_URL=<?= htmlspecialchars((isset($_SERVER['HTTPS']) ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . '/api/agent.php') ?> \
  -e AGENT_TOKEN=default-agent-token-change-me \
  -e COLLECTORS=trivy,system,docker \
  trivy-agent:latest</code>
                </div>
            </div>
        </div>
        <?php else: ?>
        <div class="agents-grid">
            <?php foreach ($agents as $agent): ?>
            <div class="agent-card <?= $agent['status'] ?>">
                <div class="agent-header">
                    <div class="agent-name">🖥️ <?= htmlspecialchars($agent['hostname']) ?></div>
                    <span class="agent-status <?= $agent['status'] ?>">
                        <?= $agent['status'] === 'online' ? '🟢 온라인' : ($agent['status'] === 'error' ? '🟡 에러' : '🔴 오프라인') ?>
                    </span>
                </div>
                <div class="agent-tags">
                    <?php foreach ($agent['groups'] as $group): ?>
                    <span class="tag tag-group" style="background: <?= htmlspecialchars($group['color']) ?>">
                        <?= htmlspecialchars($group['icon'] . ' ' . $group['display_name']) ?>
                    </span>
                    <?php endforeach; ?>
                    <?php foreach ($agent['tags'] as $tag): ?>
                    <span class="tag" style="background: <?= htmlspecialchars($tag['color']) ?>">
                        <?= htmlspecialchars($tag['display_name']) ?>
                    </span>
                    <?php endforeach; ?>
                    <?php if (empty($agent['groups']) && empty($agent['tags'])): ?>
                    <span class="tag" style="background: #666">미분류</span>
                    <?php endif; ?>
                </div>
                <div class="agent-info">
                    <div>🌐 IP: <?= htmlspecialchars($agent['ip_address'] ?: 'N/A') ?></div>
                    <div>💻 OS: <?= htmlspecialchars($agent['os_info'] ?: 'N/A') ?></div>
                    <div>⏰ 마지막 통신: <?= $agent['last_heartbeat'] ? date('Y-m-d H:i:s', strtotime($agent['last_heartbeat'])) : 'N/A' ?></div>
                </div>
                <div class="agent-stats">
                    <div class="agent-stat">
                        <div class="value"><?= $agent['recent_scans'] ?></div>
                        <div class="label">24h 스캔</div>
                    </div>
                    <div class="agent-stat critical">
                        <div class="value"><?= $agent['recent_critical'] ?></div>
                        <div class="label">Critical</div>
                    </div>
                    <div class="agent-stat high">
                        <div class="value"><?= $agent['recent_high'] ?></div>
                        <div class="label">High</div>
                    </div>
                </div>
                <div class="agent-actions">
                    <button class="btn btn-primary" onclick="showAgentDetail('<?= htmlspecialchars($agent['agent_id']) ?>')">📋 상세</button>
                    <button class="btn btn-success" onclick="sendCommand('<?= htmlspecialchars($agent['agent_id']) ?>', 'scan_all')">🔍 스캔</button>
                    <button class="btn btn-warning" onclick="showTagModal('<?= htmlspecialchars($agent['agent_id']) ?>')">🏷️ 태그</button>
                </div>
            </div>
            <?php endforeach; ?>
            <?php if (empty($agents) && ($filterGroup || $filterTag || $filterStatus)): ?>
            <div class="card">
                <div class="empty-state">
                    <h3>🔍 조건에 맞는 에이전트가 없습니다</h3>
                    <p>필터를 변경하거나 초기화하세요.</p>
                </div>
            </div>
            <?php endif; ?>
        </div>
        <?php endif; ?>
        </div><!-- end tab-agents -->

        <!-- 자산 그룹 탭 -->
        <div id="tab-groups" class="tab-content">
            <div class="card">
                <h2>📁 자산 그룹별 현황</h2>
                <p style="color:#888; margin-bottom:20px;">그룹을 클릭하면 해당 그룹의 에이전트만 필터링됩니다.</p>
            </div>
            <div class="groups-grid">
                <?php foreach ($assetGroups as $group):
                    $stats = $groupStats[$group['id']] ?? ['total_critical' => 0, 'total_high' => 0, 'agent_count' => 0];
                ?>
                <div class="group-card <?= $filterGroup == $group['id'] ? 'active' : '' ?>"
                     style="border-left: 4px solid <?= htmlspecialchars($group['color']) ?>">
                    <div class="group-header">
                        <div class="group-name" onclick="applyFilter('group', <?= $group['id'] ?>)" style="cursor:pointer;">
                            <?= htmlspecialchars($group['icon'] . ' ' . $group['display_name']) ?>
                        </div>
                        <span class="group-count"><?= $stats['agent_count'] ?? 0 ?> 에이전트</span>
                        <?php if (isAdmin()): ?>
                        <button class="btn btn-sm" onclick="deleteGroup(<?= $group['id'] ?>, '<?= htmlspecialchars($group['display_name']) ?>')" style="margin-left:auto; padding:2px 6px; background:#e74c3c;">🗑️</button>
                        <?php endif; ?>
                    </div>
                    <p style="color:#888; font-size:0.85em; margin-bottom:10px;"><?= htmlspecialchars($group['description'] ?: '') ?></p>
                    <div class="group-stats" onclick="applyFilter('group', <?= $group['id'] ?>)" style="cursor:pointer;">
                        <span class="critical">🔴 Critical: <?= $stats['total_critical'] ?? 0 ?></span>
                        <span class="high">🟠 High: <?= $stats['total_high'] ?? 0 ?></span>
                    </div>
                </div>
                <?php endforeach; ?>

                <?php if (isAdmin()): ?>
                <!-- 새 그룹 추가 (Admin만) -->
                <div class="group-card" onclick="showAddGroupModal()" style="border-left: 4px solid #666; display:flex; align-items:center; justify-content:center; cursor:pointer;">
                    <span style="font-size:2em; color:#666;">➕</span>
                </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- 태그 관리 탭 -->
        <div id="tab-tags" class="tab-content">
            <div class="card">
                <h2>🏷️ 태그 관리</h2>

                <?php
                $tagsByCategory = [];
                foreach ($assetTags as $tag) {
                    $tagsByCategory[$tag['category']][] = $tag;
                }
                ?>

                <?php foreach (['environment' => '🌍 환경', 'team' => '👥 팀', 'priority' => '⚡ 우선순위', 'service' => '🔧 서비스', 'custom' => '📝 커스텀'] as $category => $label): ?>
                <div class="tag-section">
                    <h4><?= $label ?></h4>
                    <div class="tag-list">
                        <?php foreach ($tagsByCategory[$category] ?? [] as $tag): ?>
                        <span class="tag" style="background: <?= htmlspecialchars($tag['color']) ?>; cursor:pointer; position:relative;">
                            <span onclick="applyFilter('tag', <?= $tag['id'] ?>)"><?= htmlspecialchars($tag['display_name']) ?></span>
                            <?php if (isAdmin()): ?>
                            <span onclick="deleteTag(<?= $tag['id'] ?>, '<?= htmlspecialchars($tag['display_name']) ?>')"
                                  style="margin-left:5px; opacity:0.7;">&times;</span>
                            <?php endif; ?>
                        </span>
                        <?php endforeach; ?>
                        <?php if (isAdmin()): ?>
                        <span class="tag" style="background:#333; cursor:pointer;" onclick="showAddTagModal('<?= $category ?>')">+ 추가</span>
                        <?php endif; ?>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>
        </div>

    </div>

    <!-- 상세 모달 -->
    <div id="agentModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>🤖 에이전트 상세 정보</h2>
                <button class="modal-close" onclick="closeModal('agentModal')">&times;</button>
            </div>
            <div id="agentDetailContent">로딩 중...</div>
        </div>
    </div>

    <!-- 태그 관리 모달 -->
    <div id="tagModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>🏷️ 태그 관리</h2>
                <button class="modal-close" onclick="closeModal('tagModal')">&times;</button>
            </div>
            <div id="tagModalContent">로딩 중...</div>
        </div>
    </div>

    <!-- 그룹 추가 모달 -->
    <div id="addGroupModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>📁 새 자산 그룹 추가</h2>
                <button class="modal-close" onclick="closeModal('addGroupModal')">&times;</button>
            </div>
            <form onsubmit="addGroup(event)">
                <div style="margin-bottom:15px;">
                    <label style="display:block; margin-bottom:5px; color:#888;">그룹명 (영문)</label>
                    <input type="text" name="name" required style="width:100%; padding:10px; background:#16213e; border:1px solid #333; color:white; border-radius:5px;">
                </div>
                <div style="margin-bottom:15px;">
                    <label style="display:block; margin-bottom:5px; color:#888;">표시 이름</label>
                    <input type="text" name="display_name" required style="width:100%; padding:10px; background:#16213e; border:1px solid #333; color:white; border-radius:5px;">
                </div>
                <div style="margin-bottom:15px;">
                    <label style="display:block; margin-bottom:5px; color:#888;">설명</label>
                    <textarea name="description" style="width:100%; padding:10px; background:#16213e; border:1px solid #333; color:white; border-radius:5px;"></textarea>
                </div>
                <div style="display:flex; gap:10px; margin-bottom:15px;">
                    <div style="flex:1;">
                        <label style="display:block; margin-bottom:5px; color:#888;">색상</label>
                        <input type="color" name="color" value="#3498db" style="width:100%; height:40px;">
                    </div>
                    <div style="flex:1;">
                        <label style="display:block; margin-bottom:5px; color:#888;">아이콘</label>
                        <input type="text" name="icon" value="📁" style="width:100%; padding:10px; background:#16213e; border:1px solid #333; color:white; border-radius:5px;">
                    </div>
                </div>
                <button type="submit" class="btn btn-success" style="width:100%;">추가</button>
            </form>
        </div>
    </div>

    <script>
    // 탭 전환
    function showTab(tabName) {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
        document.querySelector(`[onclick="showTab('${tabName}')"]`).classList.add('active');
        document.getElementById('tab-' + tabName).classList.add('active');
    }

    // 필터 적용
    function applyFilter(type, value) {
        const url = new URL(window.location);
        if (value) {
            url.searchParams.set(type, value);
        } else {
            url.searchParams.delete(type);
        }
        window.location = url;
    }

    // 모달
    function closeModal(id) {
        document.getElementById(id).classList.remove('active');
    }

    function showAgentDetail(agentId) {
        document.getElementById('agentModal').classList.add('active');
        fetch('api/agent_admin.php?action=info&agent_id=' + encodeURIComponent(agentId))
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    const agent = data.agent;
                    let html = `
                        <h3>${agent.hostname}</h3>
                        <p><strong>Agent ID:</strong> ${agent.agent_id}</p>
                        <p><strong>IP:</strong> ${agent.ip_address}</p>
                        <p><strong>OS:</strong> ${agent.os_info}</p>
                        <p><strong>Status:</strong> ${agent.status}</p>
                        <h4 style="margin-top:20px;">최근 스캔</h4>
                        <ul>
                    `;
                    (data.recent_scans || []).slice(0, 10).forEach(scan => {
                        html += `<li>${scan.image_name} - ${scan.scan_date} (Critical: ${scan.critical_count}, High: ${scan.high_count})</li>`;
                    });
                    html += '</ul>';
                    document.getElementById('agentDetailContent').innerHTML = html;
                } else {
                    document.getElementById('agentDetailContent').innerHTML = '<p style="color:red;">' + data.error + '</p>';
                }
            });
    }

    // 태그 관리 모달
    function showTagModal(agentId) {
        document.getElementById('tagModal').classList.add('active');
        const allGroups = <?= json_encode($assetGroups) ?>;
        const allTags = <?= json_encode($assetTags) ?>;

        fetch('api/agent_admin.php?action=info&agent_id=' + encodeURIComponent(agentId))
            .then(r => r.json())
            .then(data => {
                const agentGroups = data.groups || [];
                const agentTags = data.tags || [];
                const agentGroupIds = agentGroups.map(g => g.id);
                const agentTagIds = agentTags.map(t => t.id);

                let html = `<h4 style="margin-bottom:15px;">📁 그룹</h4><div class="tag-list">`;
                allGroups.forEach(g => {
                    const active = agentGroupIds.includes(g.id) ? 'active' : '';
                    html += `<span class="tag tag-toggle ${active}" style="background:${g.color}"
                             onclick="toggleGroup('${agentId}', ${g.id}, this)">${g.icon} ${g.display_name}</span>`;
                });
                html += `</div><h4 style="margin:20px 0 15px;">🏷️ 태그</h4><div class="tag-list">`;
                allTags.forEach(t => {
                    const active = agentTagIds.includes(t.id) ? 'active' : '';
                    html += `<span class="tag tag-toggle ${active}" style="background:${t.color}"
                             onclick="toggleTag('${agentId}', ${t.id}, this)">${t.display_name}</span>`;
                });
                html += `</div>`;
                document.getElementById('tagModalContent').innerHTML = html;
            });
    }

    // 그룹 토글
    function toggleGroup(agentId, groupId, el) {
        const action = el.classList.contains('active') ? 'remove_group' : 'add_group';
        const formData = new FormData();
        formData.append('action', action);
        formData.append('agent_id', agentId);
        formData.append('group_id', groupId);

        fetch('api/agent_admin.php', { method: 'POST', body: formData })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    el.classList.toggle('active');
                }
            });
    }

    // 태그 토글
    function toggleTag(agentId, tagId, el) {
        const action = el.classList.contains('active') ? 'remove_tag' : 'add_tag';
        const formData = new FormData();
        formData.append('action', action);
        formData.append('agent_id', agentId);
        formData.append('tag_id', tagId);

        fetch('api/agent_admin.php', { method: 'POST', body: formData })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    el.classList.toggle('active');
                }
            });
    }

    // 그룹 추가
    function showAddGroupModal() {
        document.getElementById('addGroupModal').classList.add('active');
    }

    function addGroup(e) {
        e.preventDefault();
        const form = e.target;
        const formData = new FormData(form);
        formData.append('action', 'add_group');

        fetch('api/agent_admin.php', { method: 'POST', body: formData })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    location.reload();
                } else {
                    alert('오류: ' + data.error);
                }
            });
    }

    // 태그 추가
    function showAddTagModal(category) {
        const name = prompt('태그명 (영문):');
        if (!name) return;
        const displayName = prompt('표시 이름:');
        if (!displayName) return;

        const formData = new FormData();
        formData.append('action', 'add_tag');
        formData.append('name', name);
        formData.append('display_name', displayName);
        formData.append('category', category);

        fetch('api/agent_admin.php', { method: 'POST', body: formData })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    location.reload();
                } else {
                    alert('오류: ' + data.error);
                }
            });
    }

    function sendCommand(agentId, commandType, commandData = null) {
        const formData = new FormData();
        formData.append('action', 'send_command');
        formData.append('agent_id', agentId);
        formData.append('command_type', commandType);
        if (commandData) formData.append('command_data', JSON.stringify(commandData));

        fetch('api/agent_admin.php', { method: 'POST', body: formData })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    alert('명령이 전송되었습니다. (ID: ' + data.command_id + ')');
                } else {
                    alert('오류: ' + data.error);
                }
            });
    }

    // 그룹 삭제
    function deleteGroup(groupId, groupName) {
        if (!confirm(`"${groupName}" 그룹을 삭제하시겠습니까?\n\n⚠️ 해당 그룹에 할당된 모든 에이전트 매핑도 삭제됩니다.`)) return;

        const formData = new FormData();
        formData.append('action', 'delete_group');
        formData.append('group_id', groupId);

        fetch('api/agent_admin.php', { method: 'POST', body: formData })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    location.reload();
                } else {
                    alert('오류: ' + data.error);
                }
            });
    }

    // 태그 삭제
    function deleteTag(tagId, tagName) {
        if (!confirm(`"${tagName}" 태그를 삭제하시겠습니까?`)) return;

        const formData = new FormData();
        formData.append('action', 'delete_tag');
        formData.append('tag_id', tagId);

        fetch('api/agent_admin.php', { method: 'POST', body: formData })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    location.reload();
                } else {
                    alert('오류: ' + data.error);
                }
            });
    }
    </script>
</body>
</html>

