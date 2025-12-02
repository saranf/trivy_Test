<?php
/**
 * 🛠️ Agent Admin API - 관리자용 에이전트 관리
 * 
 * Endpoints:
 * - GET  ?action=list           - 에이전트 목록
 * - GET  ?action=info           - 에이전트 상세
 * - POST ?action=send_command   - 명령 전송
 * - POST ?action=delete         - 에이전트 삭제
 * - GET  ?action=data           - 에이전트 데이터 조회
 * - GET  ?action=scans          - 에이전트별 스캔 기록
 */

require_once __DIR__ . '/../auth.php';
require_once __DIR__ . '/../db_functions.php';

header('Content-Type: application/json');

// 로그인 확인
if (!isAuthenticated()) {
    echo json_encode(['success' => false, 'error' => '로그인이 필요합니다.']);
    exit;
}

// Admin/Operator만 접근 가능
if (!isOperator()) {
    echo json_encode(['success' => false, 'error' => '권한이 없습니다.']);
    exit;
}

$conn = getDbConnection();
if (!$conn) {
    echo json_encode(['success' => false, 'error' => 'DB 연결 실패']);
    exit;
}

initDatabase($conn);

$action = $_GET['action'] ?? $_POST['action'] ?? '';

switch ($action) {
    // 에이전트 목록
    case 'list':
        markOfflineAgents($conn);
        $status = $_GET['status'] ?? null;
        $agents = getAgents($conn, $status);
        
        // 각 에이전트별 최근 스캔 수 추가
        foreach ($agents as &$agent) {
            $stmt = $conn->prepare("
                SELECT COUNT(*) as scan_count, 
                       SUM(critical_count) as total_critical,
                       SUM(high_count) as total_high
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
        
        echo json_encode(['success' => true, 'agents' => $agents]);
        break;

    // 에이전트 상세 정보
    case 'info':
        $agentId = $_GET['agent_id'] ?? '';
        if (empty($agentId)) {
            echo json_encode(['success' => false, 'error' => 'agent_id 필요']);
            exit;
        }
        
        $agent = getAgent($conn, $agentId);
        if (!$agent) {
            echo json_encode(['success' => false, 'error' => '에이전트를 찾을 수 없습니다.']);
            exit;
        }
        
        // 최근 데이터
        $recentData = getAgentData($conn, $agentId, null, 50);
        
        // 최근 스캔
        $recentScans = getScanHistoryByAgent($conn, $agentId, 20);
        
        // 최근 명령
        $stmt = $conn->prepare("SELECT * FROM agent_commands WHERE agent_id = ? ORDER BY created_at DESC LIMIT 20");
        $stmt->bind_param("s", $agentId);
        $stmt->execute();
        $commands = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        $stmt->close();
        
        echo json_encode([
            'success' => true,
            'agent' => $agent,
            'recent_data' => $recentData,
            'recent_scans' => $recentScans,
            'recent_commands' => $commands
        ]);
        break;

    // 명령 전송
    case 'send_command':
        if (!isAdmin()) {
            echo json_encode(['success' => false, 'error' => 'Admin 권한 필요']);
            exit;
        }
        
        $agentId = $_POST['agent_id'] ?? '';
        $commandType = $_POST['command_type'] ?? '';
        $commandData = $_POST['command_data'] ?? null;
        
        if (empty($agentId) || empty($commandType)) {
            echo json_encode(['success' => false, 'error' => 'agent_id와 command_type 필요']);
            exit;
        }
        
        if ($commandData && is_string($commandData)) {
            $commandData = json_decode($commandData, true);
        }
        
        $commandId = addAgentCommand($conn, $agentId, $commandType, $commandData);
        
        if ($commandId) {
            // 감사 로그
            auditLog($conn, 'SEND_AGENT_COMMAND', 'agent', null, "agent: {$agentId}, type: {$commandType}");
            echo json_encode(['success' => true, 'command_id' => $commandId]);
        } else {
            echo json_encode(['success' => false, 'error' => '명령 전송 실패']);
        }
        break;

    // 에이전트별 데이터 조회
    case 'data':
        $agentId = $_GET['agent_id'] ?? '';
        $dataType = $_GET['data_type'] ?? null;
        $limit = min((int)($_GET['limit'] ?? 100), 500);
        
        if (empty($agentId)) {
            echo json_encode(['success' => false, 'error' => 'agent_id 필요']);
            exit;
        }
        
        $data = getAgentData($conn, $agentId, $dataType, $limit);
        echo json_encode(['success' => true, 'data' => $data]);
        break;

    // 에이전트별 스캔 기록
    case 'scans':
        $agentId = $_GET['agent_id'] ?? null;
        $limit = min((int)($_GET['limit'] ?? 50), 200);
        
        $scans = getScanHistoryByAgent($conn, $agentId, $limit);
        echo json_encode(['success' => true, 'scans' => $scans]);
        break;

    default:
        echo json_encode(['success' => false, 'error' => '알 수 없는 액션']);
}

$conn->close();

