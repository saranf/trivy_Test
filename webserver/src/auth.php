<?php
/**
 * 인증 및 권한 관리 헬퍼
 */
session_start();

require_once 'db_functions.php';

// 로그인 확인
function requireLogin() {
    if (!isset($_SESSION['user'])) {
        header('Location: login.php');
        exit;
    }
    return $_SESSION['user'];
}

// 권한 확인 (viewer < operator < admin)
function requireRole($minRole) {
    $user = requireLogin();
    $levels = ['viewer' => 1, 'operator' => 2, 'admin' => 3];
    $userLevel = $levels[$user['role']] ?? 0;
    $requiredLevel = $levels[$minRole] ?? 99;

    if ($userLevel < $requiredLevel) {
        http_response_code(403);
        echo "<script>alert('권한이 없습니다. ({$minRole} 이상 필요)'); history.back();</script>";
        exit;
    }
    return $user;
}

// 현재 사용자 정보
function getCurrentUser() {
    return $_SESSION['user'] ?? null;
}

// 로그인 상태 확인
function isLoggedIn() {
    return isset($_SESSION['user']);
}

// 역할 확인
function isAdmin() {
    return ($_SESSION['user']['role'] ?? '') === 'admin';
}

function isOperator() {
    return in_array($_SESSION['user']['role'] ?? '', ['operator', 'admin']);
}

function isViewer() {
    return isset($_SESSION['user']);
}

// 로그아웃
function logout() {
    $conn = getDbConnection();
    if ($conn && isset($_SESSION['user'])) {
        logAudit($conn, $_SESSION['user']['id'], $_SESSION['user']['username'], 'LOGOUT', 'user', $_SESSION['user']['id'], null);
        $conn->close();
    }
    session_destroy();
    header('Location: login.php');
    exit;
}

// 감사 로그 기록 (세션 사용자 기준)
function auditLog($conn, $action, $targetType = null, $targetId = null, $details = null) {
    $user = getCurrentUser();
    if ($user) {
        logAudit($conn, $user['id'], $user['username'], $action, $targetType, $targetId, $details);
    } else {
        logAudit($conn, null, 'anonymous', $action, $targetType, $targetId, $details);
    }
}

// 권한별 네비게이션 메뉴 생성
function getNavMenu() {
    $user = getCurrentUser();
    if (!$user) return '';

    $menu = '<div class="nav-menu">';
    $menu .= '<a href="index.php">🏠 메인</a>';
    $menu .= '<a href="scan_history.php">📋 스캔 기록</a>';

    if (isOperator()) {
        $menu .= '<a href="container_scan.php">🔍 컨테이너 스캔</a>';
        $menu .= '<a href="exceptions.php">🛡️ 예외 관리</a>';
    }

    if (isAdmin()) {
        $menu .= '<a href="scheduled_scans.php">⏰ 주기적 스캔</a>';
        $menu .= '<a href="users.php">👥 사용자 관리</a>';
        $menu .= '<a href="audit_logs.php">📜 감사 로그</a>';
    }

    $menu .= '<span class="nav-user">';
    $menu .= '<span class="role-badge role-' . $user['role'] . '">' . strtoupper($user['role']) . '</span> ';
    $menu .= htmlspecialchars($user['username']);
    $menu .= ' <a href="logout.php" class="btn-logout">로그아웃</a>';
    $menu .= '</span>';
    $menu .= '</div>';

    return $menu;
}

// 공통 스타일
function getAuthStyles() {
    return '
    .nav-menu { background: #1a1a2e; padding: 15px 20px; display: flex; gap: 15px; align-items: center; flex-wrap: wrap; }
    .nav-menu a { color: white; text-decoration: none; padding: 8px 15px; border-radius: 5px; font-size: 14px; }
    .nav-menu a:hover { background: rgba(255,255,255,0.1); }
    .nav-user { margin-left: auto; color: white; display: flex; align-items: center; gap: 10px; }
    .btn-logout { background: #dc3545 !important; padding: 6px 12px !important; border-radius: 4px !important; font-size: 12px !important; }
    .role-badge { display: inline-block; padding: 3px 8px; border-radius: 10px; font-size: 10px; font-weight: bold; }
    .role-admin { background: #dc3545; color: white; }
    .role-operator { background: #28a745; color: white; }
    .role-viewer { background: #6c757d; color: white; }
    ';
}

