<?php
/**
 * 🤖 Agent API - Central Server Endpoint
 * 
 * Endpoints:
 * - POST /api/agent.php?action=register   - 에이전트 등록
 * - POST /api/agent.php?action=heartbeat  - 하트비트
 * - POST /api/agent.php?action=report     - 데이터 보고
 * - GET  /api/agent.php?action=commands   - 대기 명령 조회
 * - POST /api/agent.php?action=command_result - 명령 결과 보고
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-Agent-Token');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

require_once __DIR__ . '/../db_functions.php';

// 에이전트 인증 토큰 확인
function verifyAgentToken($token) {
    // 환경변수 또는 DB에서 토큰 검증
    $validToken = getenv('AGENT_API_TOKEN') ?: 'default-agent-token-change-me';
    return hash_equals($validToken, $token);
}

// 요청 본문 파싱
function getRequestBody() {
    $body = file_get_contents('php://input');
    return json_decode($body, true) ?: [];
}

// 응답 전송
function sendResponse($success, $data = null, $error = null, $code = 200) {
    http_response_code($code);
    echo json_encode([
        'success' => $success,
        'data' => $data,
        'error' => $error,
        'timestamp' => date('c')
    ]);
    exit;
}

// 토큰 검증
$token = $_SERVER['HTTP_X_AGENT_TOKEN'] ?? '';
if (!verifyAgentToken($token)) {
    sendResponse(false, null, 'Invalid or missing agent token', 401);
}

$conn = getDbConnection();
if (!$conn) {
    sendResponse(false, null, 'Database connection failed', 500);
}

initDatabase($conn);

$action = $_GET['action'] ?? $_POST['action'] ?? '';
$body = getRequestBody();

switch ($action) {
    // ========================================
    // 에이전트 등록
    // ========================================
    case 'register':
        $agentId = $body['agent_id'] ?? '';
        $hostname = $body['hostname'] ?? '';
        $ipAddress = $body['ip_address'] ?? $_SERVER['REMOTE_ADDR'] ?? '';
        $osInfo = $body['os_info'] ?? '';
        $version = $body['version'] ?? '1.0.0';
        $config = $body['config'] ?? null;
        $tags = $body['tags'] ?? null;

        if (empty($agentId) || empty($hostname)) {
            sendResponse(false, null, 'agent_id and hostname are required', 400);
        }

        $result = registerAgent($conn, $agentId, $hostname, $ipAddress, $osInfo, $version, $config, $tags);
        
        if ($result) {
            // 등록 시 대기 중인 명령도 함께 반환
            $commands = getPendingCommands($conn, $agentId);
            sendResponse(true, [
                'message' => 'Agent registered successfully',
                'agent_id' => $agentId,
                'pending_commands' => $commands
            ]);
        } else {
            sendResponse(false, null, 'Failed to register agent', 500);
        }
        break;

    // ========================================
    // 하트비트
    // ========================================
    case 'heartbeat':
        $agentId = $body['agent_id'] ?? '';
        
        if (empty($agentId)) {
            sendResponse(false, null, 'agent_id is required', 400);
        }

        updateAgentHeartbeat($conn, $agentId);
        
        // 대기 중인 명령 반환
        $commands = getPendingCommands($conn, $agentId);
        
        sendResponse(true, [
            'commands' => $commands,
            'server_time' => date('c')
        ]);
        break;

    // ========================================
    // 데이터 보고 (확장 가능)
    // ========================================
    case 'report':
        $agentId = $body['agent_id'] ?? '';
        $dataType = $body['data_type'] ?? '';
        $data = $body['data'] ?? [];

        if (empty($agentId) || empty($dataType)) {
            sendResponse(false, null, 'agent_id and data_type are required', 400);
        }

        // 하트비트 업데이트
        updateAgentHeartbeat($conn, $agentId);

        $results = [];
        
        // 데이터 타입별 처리
        switch ($dataType) {
            case 'trivy_scan':
                // Trivy 스캔 결과
                foreach ($data as $scanResult) {
                    $imageName = $scanResult['image'] ?? 'unknown';
                    $trivyData = $scanResult['result'] ?? $scanResult;
                    $scanId = saveScanResultFromAgent($conn, $agentId, $imageName, $trivyData, 'agent');
                    $results[] = ['image' => $imageName, 'scan_id' => $scanId];
                }
                break;

            case 'system_info':
            case 'processes':
            case 'iptables':
            case 'network':
            case 'files':
            default:
                // 범용 데이터 저장
                foreach ($data as $key => $value) {
                    $dataKey = is_numeric($key) ? null : $key;
                    saveAgentData($conn, $agentId, $dataType, $dataKey, $value);
                }
                $results = ['saved' => count($data)];
                break;
        }

        sendResponse(true, ['results' => $results]);
        break;

    // ========================================
    // 대기 명령 조회
    // ========================================
    case 'commands':
        $agentId = $_GET['agent_id'] ?? $body['agent_id'] ?? '';

        if (empty($agentId)) {
            sendResponse(false, null, 'agent_id is required', 400);
        }

        $commands = getPendingCommands($conn, $agentId);
        sendResponse(true, ['commands' => $commands]);
        break;

    // ========================================
    // 명령 결과 보고
    // ========================================
    case 'command_result':
        $commandId = $body['command_id'] ?? 0;
        $status = $body['status'] ?? 'completed';
        $result = $body['result'] ?? null;

        if (empty($commandId)) {
            sendResponse(false, null, 'command_id is required', 400);
        }

        $updated = updateCommandResult($conn, $commandId, $status, $result);
        sendResponse($updated, ['message' => 'Command result updated']);
        break;

    // ========================================
    // 에이전트 정보 조회 (관리자용)
    // ========================================
    case 'list':
        // 오프라인 에이전트 마킹
        markOfflineAgents($conn);

        $status = $_GET['status'] ?? null;
        $agents = getAgents($conn, $status);
        sendResponse(true, ['agents' => $agents]);
        break;

    case 'info':
        $agentId = $_GET['agent_id'] ?? '';
        if (empty($agentId)) {
            sendResponse(false, null, 'agent_id is required', 400);
        }

        $agent = getAgent($conn, $agentId);
        if (!$agent) {
            sendResponse(false, null, 'Agent not found', 404);
        }

        $recentData = getAgentData($conn, $agentId, null, 20);
        sendResponse(true, ['agent' => $agent, 'recent_data' => $recentData]);
        break;

    default:
        sendResponse(false, null, 'Unknown action: ' . $action, 400);
}

$conn->close();

