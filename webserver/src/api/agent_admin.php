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
if (!isLoggedIn()) {
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

        // 그룹/태그 정보
        $groups = getAgentGroups($conn, $agentId);
        $tags = getAgentTags($conn, $agentId);

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
            'groups' => $groups,
            'tags' => $tags,
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

    // ========================================
    // 자산 그룹/태그 관리
    // ========================================

    // 그룹 추가 또는 에이전트에 그룹 할당
    case 'add_group':
        // 에이전트에 그룹 할당하는 경우
        if (!empty($_POST['agent_id']) && !empty($_POST['group_id'])) {
            $agentId = $_POST['agent_id'];
            $groupId = (int)$_POST['group_id'];

            if (assignAgentToGroup($conn, $agentId, $groupId)) {
                echo json_encode(['success' => true]);
            } else {
                echo json_encode(['success' => false, 'error' => '그룹 할당 실패']);
            }
        }
        // 새 그룹 생성하는 경우
        else {
            $name = $_POST['name'] ?? '';
            $displayName = $_POST['display_name'] ?? '';
            $description = $_POST['description'] ?? '';
            $color = $_POST['color'] ?? '#3498db';
            $icon = $_POST['icon'] ?? '📁';

            if (empty($name) || empty($displayName)) {
                echo json_encode(['success' => false, 'error' => 'name과 display_name 필요']);
                exit;
            }

            $groupId = createAssetGroup($conn, $name, $displayName, $description, $color, $icon);
            if ($groupId) {
                auditLog($conn, 'CREATE_ASSET_GROUP', 'asset_group', $groupId, "그룹 생성: {$displayName}");
                echo json_encode(['success' => true, 'group_id' => $groupId]);
            } else {
                echo json_encode(['success' => false, 'error' => '그룹 생성 실패 (중복 이름?)']);
            }
        }
        break;

    // 태그 추가 또는 에이전트에 태그 할당
    case 'add_tag':
        // 에이전트에 태그 할당하는 경우
        if (!empty($_POST['agent_id']) && !empty($_POST['tag_id'])) {
            $agentId = $_POST['agent_id'];
            $tagId = (int)$_POST['tag_id'];

            if (assignAgentTag($conn, $agentId, $tagId)) {
                echo json_encode(['success' => true]);
            } else {
                echo json_encode(['success' => false, 'error' => '태그 할당 실패']);
            }
        }
        // 새 태그 생성하는 경우
        else {
            $name = $_POST['name'] ?? '';
            $displayName = $_POST['display_name'] ?? '';
            $color = $_POST['color'] ?? '#9b59b6';
            $category = $_POST['category'] ?? 'custom';

            if (empty($name) || empty($displayName)) {
                echo json_encode(['success' => false, 'error' => 'name과 display_name 필요']);
                exit;
            }

            $tagId = createAssetTag($conn, $name, $displayName, $color, $category);
            if ($tagId) {
                auditLog($conn, 'CREATE_ASSET_TAG', 'asset_tag', $tagId, "태그 생성: {$displayName}");
                echo json_encode(['success' => true, 'tag_id' => $tagId]);
            } else {
                echo json_encode(['success' => false, 'error' => '태그 생성 실패 (중복 이름?)']);
            }
        }
        break;

    // 에이전트에서 그룹 제거
    case 'remove_group':
        $agentId = $_POST['agent_id'] ?? '';
        $groupId = (int)($_POST['group_id'] ?? 0);

        if (empty($agentId) || !$groupId) {
            echo json_encode(['success' => false, 'error' => 'agent_id와 group_id 필요']);
            exit;
        }

        if (removeAgentFromGroup($conn, $agentId, $groupId)) {
            echo json_encode(['success' => true]);
        } else {
            echo json_encode(['success' => false, 'error' => '그룹 제거 실패']);
        }
        break;

    // 에이전트에서 태그 제거
    case 'remove_tag':
        $agentId = $_POST['agent_id'] ?? '';
        $tagId = (int)($_POST['tag_id'] ?? 0);

        if (empty($agentId) || !$tagId) {
            echo json_encode(['success' => false, 'error' => 'agent_id와 tag_id 필요']);
            exit;
        }

        if (removeAgentTag($conn, $agentId, $tagId)) {
            echo json_encode(['success' => true]);
        } else {
            echo json_encode(['success' => false, 'error' => '태그 제거 실패']);
        }
        break;

    // 그룹 목록
    case 'groups':
        $groups = getAssetGroups($conn);
        echo json_encode(['success' => true, 'groups' => $groups]);
        break;

    // 태그 목록
    case 'tags':
        $category = $_GET['category'] ?? null;
        $tags = getAssetTags($conn, $category);
        echo json_encode(['success' => true, 'tags' => $tags]);
        break;

    // 그룹 삭제 (Admin만)
    case 'delete_group':
        if (!isAdmin()) {
            echo json_encode(['success' => false, 'error' => 'Admin 권한 필요']);
            exit;
        }
        $groupId = (int)($_POST['group_id'] ?? 0);
        if (!$groupId) {
            echo json_encode(['success' => false, 'error' => 'group_id 필요']);
            exit;
        }
        // 매핑 먼저 삭제
        $conn->query("DELETE FROM agent_group_mapping WHERE group_id = {$groupId}");
        // 그룹 삭제
        $stmt = $conn->prepare("DELETE FROM asset_groups WHERE id = ?");
        $stmt->bind_param("i", $groupId);
        if ($stmt->execute()) {
            auditLog($conn, 'DELETE_ASSET_GROUP', 'asset_group', $groupId, "그룹 삭제");
            echo json_encode(['success' => true]);
        } else {
            echo json_encode(['success' => false, 'error' => '삭제 실패']);
        }
        $stmt->close();
        break;

    // 태그 삭제 (Admin만)
    case 'delete_tag':
        if (!isAdmin()) {
            echo json_encode(['success' => false, 'error' => 'Admin 권한 필요']);
            exit;
        }
        $tagId = (int)($_POST['tag_id'] ?? 0);
        if (!$tagId) {
            echo json_encode(['success' => false, 'error' => 'tag_id 필요']);
            exit;
        }
        // 매핑 먼저 삭제
        $conn->query("DELETE FROM agent_tag_mapping WHERE tag_id = {$tagId}");
        // 태그 삭제
        $stmt = $conn->prepare("DELETE FROM asset_tags WHERE id = ?");
        $stmt->bind_param("i", $tagId);
        if ($stmt->execute()) {
            auditLog($conn, 'DELETE_ASSET_TAG', 'asset_tag', $tagId, "태그 삭제");
            echo json_encode(['success' => true]);
        } else {
            echo json_encode(['success' => false, 'error' => '삭제 실패']);
        }
        $stmt->close();
        break;

    // 그룹 수정 (Admin만)
    case 'update_group':
        if (!isAdmin()) {
            echo json_encode(['success' => false, 'error' => 'Admin 권한 필요']);
            exit;
        }
        $groupId = (int)($_POST['group_id'] ?? 0);
        $displayName = $_POST['display_name'] ?? '';
        $description = $_POST['description'] ?? '';
        $color = $_POST['color'] ?? '#3498db';
        $icon = $_POST['icon'] ?? '📁';

        if (!$groupId) {
            echo json_encode(['success' => false, 'error' => 'group_id 필요']);
            exit;
        }

        $stmt = $conn->prepare("UPDATE asset_groups SET display_name=?, description=?, color=?, icon=? WHERE id=?");
        $stmt->bind_param("ssssi", $displayName, $description, $color, $icon, $groupId);
        if ($stmt->execute()) {
            echo json_encode(['success' => true]);
        } else {
            echo json_encode(['success' => false, 'error' => '수정 실패']);
        }
        $stmt->close();
        break;

    // 에이전트 삭제 (Admin만)
    case 'delete_agent':
        if (!isAdmin()) {
            echo json_encode(['success' => false, 'error' => 'Admin 권한 필요']);
            exit;
        }
        $agentId = $_POST['agent_id'] ?? '';
        if (empty($agentId)) {
            echo json_encode(['success' => false, 'error' => 'agent_id 필요']);
            exit;
        }

        // 관련 데이터도 삭제
        $conn->query("DELETE FROM agent_tag_mapping WHERE agent_id = '" . $conn->real_escape_string($agentId) . "'");
        $conn->query("DELETE FROM agent_group_mapping WHERE agent_id = '" . $conn->real_escape_string($agentId) . "'");
        $conn->query("DELETE FROM agent_data WHERE agent_id = '" . $conn->real_escape_string($agentId) . "'");
        $conn->query("DELETE FROM agent_commands WHERE agent_id = '" . $conn->real_escape_string($agentId) . "'");

        $stmt = $conn->prepare("DELETE FROM agents WHERE agent_id = ?");
        $stmt->bind_param("s", $agentId);
        if ($stmt->execute()) {
            auditLog($conn, 'DELETE_AGENT', 'agent', null, "에이전트 삭제: $agentId");
            echo json_encode(['success' => true, 'message' => '에이전트 삭제됨']);
        } else {
            echo json_encode(['success' => false, 'error' => '삭제 실패']);
        }
        $stmt->close();
        break;

    // 중복/오프라인 에이전트 일괄 삭제 (Admin만)
    case 'cleanup_agents':
        if (!isAdmin()) {
            echo json_encode(['success' => false, 'error' => 'Admin 권한 필요']);
            exit;
        }

        // hostname 기준으로 중복된 것 중 오래된 것 삭제 (최신 1개만 유지)
        $result = $conn->query("
            SELECT agent_id FROM agents a
            WHERE EXISTS (
                SELECT 1 FROM agents b
                WHERE b.hostname = a.hostname
                AND b.last_heartbeat > a.last_heartbeat
            )
        ");

        $deleted = 0;
        if ($result) {
            while ($row = $result->fetch_assoc()) {
                $agentId = $row['agent_id'];
                $conn->query("DELETE FROM agent_tag_assignments WHERE agent_id = '" . $conn->real_escape_string($agentId) . "'");
                $conn->query("DELETE FROM agent_group_assignments WHERE agent_id = '" . $conn->real_escape_string($agentId) . "'");
                $conn->query("DELETE FROM agent_data WHERE agent_id = '" . $conn->real_escape_string($agentId) . "'");
                $conn->query("DELETE FROM agent_commands WHERE agent_id = '" . $conn->real_escape_string($agentId) . "'");
                $conn->query("DELETE FROM agents WHERE agent_id = '" . $conn->real_escape_string($agentId) . "'");
                $deleted++;
            }
        }

        auditLog($conn, 'CLEANUP_AGENTS', 'agent', null, "중복 에이전트 $deleted 개 삭제");
        echo json_encode(['success' => true, 'deleted' => $deleted, 'message' => "$deleted 개 중복 에이전트 삭제됨"]);
        break;

    // 모든 에이전트 삭제 (Admin만)
    case 'delete_all_agents':
        if (!isAdmin()) {
            echo json_encode(['success' => false, 'error' => 'Admin 권한 필요']);
            exit;
        }

        // 에이전트 수 확인
        $countResult = $conn->query("SELECT COUNT(*) as cnt FROM agents");
        $count = $countResult ? $countResult->fetch_assoc()['cnt'] : 0;

        // 관련 데이터 먼저 삭제
        $conn->query("DELETE FROM agent_tag_mapping");
        $conn->query("DELETE FROM agent_group_mapping");
        $conn->query("DELETE FROM agent_data");
        $conn->query("DELETE FROM agent_commands");
        $conn->query("DELETE FROM agents");

        auditLog($conn, 'DELETE_ALL_AGENTS', 'agent', null, "모든 에이전트 $count 개 삭제");
        echo json_encode(['success' => true, 'deleted' => $count, 'message' => "모든 에이전트 $count 개 삭제됨"]);
        break;

    default:
        echo json_encode(['success' => false, 'error' => '알 수 없는 액션']);
}

$conn->close();

