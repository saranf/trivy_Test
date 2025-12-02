<?php
/**
 * 🤖 에이전트 관리 페이지
 * - 등록된 에이전트 목록
 * - 에이전트 상태 모니터링
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
$agents = getAgents($conn);

// 각 에이전트별 통계 추가
foreach ($agents as &$agent) {
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
}
unset($agent);

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
        
        /* Modal */
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 1000; align-items: center; justify-content: center; }
        .modal.active { display: flex; }
        .modal-content { background: #1a1a2e; border-radius: 10px; padding: 30px; max-width: 800px; width: 90%; max-height: 80vh; overflow-y: auto; }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .modal-close { background: none; border: none; color: white; font-size: 1.5em; cursor: pointer; }
    </style>
</head>
<body>
    <?= getNavMenu() ?>
    <div class="container">
        <h1>🤖 에이전트 관리</h1>
        
        <?php 
        $onlineCount = count(array_filter($agents, fn($a) => $a['status'] === 'online'));
        $offlineCount = count(array_filter($agents, fn($a) => $a['status'] === 'offline'));
        ?>
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

        <?php if (empty($agents)): ?>
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
                <div class="agent-info">
                    <div>🆔 Agent ID: <code><?= htmlspecialchars(substr($agent['agent_id'], 0, 20)) ?>...</code></div>
                    <div>🌐 IP: <?= htmlspecialchars($agent['ip_address'] ?: 'N/A') ?></div>
                    <div>💻 OS: <?= htmlspecialchars($agent['os_info'] ?: 'N/A') ?></div>
                    <div>📦 버전: <?= htmlspecialchars($agent['agent_version'] ?: 'N/A') ?></div>
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
                    <button class="btn btn-success" onclick="sendCommand('<?= htmlspecialchars($agent['agent_id']) ?>', 'scan_all')">🔍 전체 스캔</button>
                    <button class="btn btn-warning" onclick="sendCommand('<?= htmlspecialchars($agent['agent_id']) ?>', 'collect', {collector: 'system'})">📊 시스템 수집</button>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>
    </div>

    <!-- 상세 모달 -->
    <div id="agentModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>🤖 에이전트 상세 정보</h2>
                <button class="modal-close" onclick="closeModal()">&times;</button>
            </div>
            <div id="agentDetailContent">로딩 중...</div>
        </div>
    </div>

    <script>
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

    function closeModal() {
        document.getElementById('agentModal').classList.remove('active');
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
    </script>
</body>
</html>

