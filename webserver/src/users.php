<?php
require_once 'auth.php';
$user = requireRole('admin');
$conn = getDbConnection();
initDatabase($conn);

$message = '';
$error = '';
$activeTab = $_GET['tab'] ?? 'users';

// 액션 처리
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'create') {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        $role = $_POST['role'] ?? 'viewer';
        $email = trim($_POST['email'] ?? '');

        if (empty($username) || empty($password)) {
            $error = '사용자명과 비밀번호는 필수입니다.';
        } elseif (strlen($password) < 6) {
            $error = '비밀번호는 6자 이상이어야 합니다.';
        } else {
            $result = createUser($conn, $username, $password, $role, $email);
            if ($result['success']) {
                $message = "사용자 '{$username}'가 생성되었습니다.";
                auditLog($conn, 'CREATE_USER', 'user', $result['user_id'], "role: {$role}");
            } else {
                $error = $result['error'];
            }
        }
    } elseif ($action === 'update_role') {
        $userId = (int)($_POST['user_id'] ?? 0);
        $newRole = $_POST['role'] ?? '';
        if ($userId > 0 && $userId != $user['id']) {
            $result = updateUserRole($conn, $userId, $newRole);
            if ($result['success']) {
                $message = '권한이 변경되었습니다.';
                auditLog($conn, 'UPDATE_USER_ROLE', 'user', $userId, "new_role: {$newRole}");
            } else {
                $error = $result['error'];
            }
        }
    } elseif ($action === 'delete') {
        $userId = (int)($_POST['user_id'] ?? 0);
        if ($userId > 0 && $userId != $user['id']) {
            deleteUser($conn, $userId);
            $message = '사용자가 비활성화되었습니다.';
            auditLog($conn, 'DELETE_USER', 'user', $userId, null);
        }
    } elseif ($action === 'reset_password') {
        $userId = (int)($_POST['user_id'] ?? 0);
        $newPassword = $_POST['new_password'] ?? '';
        if ($userId > 0 && strlen($newPassword) >= 6) {
            changePassword($conn, $userId, $newPassword);
            $message = '비밀번호가 초기화되었습니다.';
            auditLog($conn, 'RESET_PASSWORD', 'user', $userId, null);
        } else {
            $error = '비밀번호는 6자 이상이어야 합니다.';
        }
    } elseif ($action === 'update_role_permission') {
        $role = $_POST['role'] ?? '';
        $permKey = $_POST['permission_key'] ?? '';
        $isAllowed = (int)($_POST['is_allowed'] ?? 0);
        if ($role && $permKey && $role !== 'admin') {
            updateRolePermission($conn, $role, $permKey, $isAllowed);
            clearPermissionCache(); // 권한 캐시 초기화
            $message = "Role '{$role}'의 권한이 업데이트되었습니다.";
            auditLog($conn, 'UPDATE_ROLE_PERMISSION', 'permission', null, "role: {$role}, perm: {$permKey}, allowed: {$isAllowed}");
        }
        $activeTab = 'role_permissions';
    } elseif ($action === 'update_user_permission') {
        $userId = (int)($_POST['user_id'] ?? 0);
        $permKey = $_POST['permission_key'] ?? '';
        $isAllowed = (int)($_POST['is_allowed'] ?? 0);
        if ($userId > 0 && $permKey) {
            updateUserPermission($conn, $userId, $permKey, $isAllowed);
            clearPermissionCache(); // 권한 캐시 초기화
            $message = "사용자별 권한이 업데이트되었습니다.";
            auditLog($conn, 'UPDATE_USER_PERMISSION', 'permission', $userId, "perm: {$permKey}, allowed: {$isAllowed}");
        }
        $activeTab = 'user_permissions';
    } elseif ($action === 'reset_user_permissions') {
        $userId = (int)($_POST['user_id'] ?? 0);
        if ($userId > 0) {
            resetUserPermission($conn, $userId);
            clearPermissionCache(); // 권한 캐시 초기화
            $message = "사용자별 권한이 Role 기본값으로 초기화되었습니다.";
            auditLog($conn, 'RESET_USER_PERMISSION', 'permission', $userId, null);
        }
        $activeTab = 'user_permissions';
    }
}

$users = getUsers($conn);
$permissionKeys = getPermissionKeys();
$allRolePermissions = getAllRolePermissions($conn);
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>사용자 관리 - Container Security</title>
    <style>
        <?= getAuthStyles() ?>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        h1 { color: #333; }
        .card { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .card h2 { margin-top: 0; font-size: 18px; color: #333; border-bottom: 1px solid #eee; padding-bottom: 10px; }
        .form-row { display: flex; gap: 15px; flex-wrap: wrap; margin-bottom: 15px; }
        .form-group { flex: 1; min-width: 150px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: 600; font-size: 13px; }
        .form-group input, .form-group select { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }
        .btn { padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; }
        .btn-primary { background: #007bff; color: white; }
        .btn-danger { background: #dc3545; color: white; }
        .btn-secondary { background: #6c757d; color: white; }
        .btn-warning { background: #ffc107; color: #333; }
        .btn:hover { opacity: 0.9; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; font-weight: 600; }
        .message { padding: 12px; border-radius: 4px; margin-bottom: 15px; }
        .message.success { background: #d4edda; color: #155724; }
        .message.error { background: #f8d7da; color: #721c24; }
        .actions { display: flex; gap: 5px; }
        .actions form { display: inline; }
        .actions select { padding: 5px; font-size: 12px; }
        .actions .btn { padding: 5px 10px; font-size: 12px; }
        .inactive { opacity: 0.5; }
        /* 탭 스타일 */
        .tabs { display: flex; gap: 5px; margin-bottom: 20px; background: white; padding: 10px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .tab-btn { padding: 12px 24px; border: none; background: #f0f0f0; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 500; transition: all 0.2s; }
        .tab-btn:hover { background: #e0e0e0; }
        .tab-btn.active { background: #007bff; color: white; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        /* 토글 스위치 */
        .toggle { position: relative; display: inline-block; width: 50px; height: 26px; }
        .toggle input { opacity: 0; width: 0; height: 0; }
        .toggle-slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background: #ccc; transition: 0.3s; border-radius: 26px; }
        .toggle-slider:before { position: absolute; content: ""; height: 20px; width: 20px; left: 3px; bottom: 3px; background: white; transition: 0.3s; border-radius: 50%; }
        .toggle input:checked + .toggle-slider { background: #28a745; }
        .toggle input:checked + .toggle-slider:before { transform: translateX(24px); }
        .toggle input:disabled + .toggle-slider { background: #28a745; opacity: 0.7; cursor: not-allowed; }
        .perm-table th { text-align: center; }
        .perm-table td { text-align: center; }
        .perm-table td:first-child { text-align: left; font-weight: 500; }
        .perm-group { background: #f8f9fa; font-weight: 600; }
        .admin-locked { color: #28a745; font-weight: bold; }
    </style>
</head>
<body>
    <?= getNavMenu() ?>
    <div class="container">
        <h1>👥 사용자 및 권한 관리</h1>

        <?php if ($message): ?><div class="message success"><?= htmlspecialchars($message) ?></div><?php endif; ?>
        <?php if ($error): ?><div class="message error"><?= htmlspecialchars($error) ?></div><?php endif; ?>

        <!-- 탭 버튼 -->
        <div class="tabs">
            <button class="tab-btn <?= $activeTab === 'users' ? 'active' : '' ?>" onclick="showTab('users')">👥 사용자 관리</button>
            <button class="tab-btn <?= $activeTab === 'role_permissions' ? 'active' : '' ?>" onclick="showTab('role_permissions')">🔐 Role별 권한</button>
            <button class="tab-btn <?= $activeTab === 'user_permissions' ? 'active' : '' ?>" onclick="showTab('user_permissions')">👤 개별 사용자 권한</button>
        </div>

        <!-- 탭 1: 사용자 관리 -->
        <div id="tab-users" class="tab-content <?= $activeTab === 'users' ? 'active' : '' ?>">
            <div class="card">
                <h2>➕ 새 사용자 생성</h2>
                <form method="post">
                    <input type="hidden" name="action" value="create">
                    <div class="form-row">
                        <div class="form-group"><label>사용자명 *</label><input type="text" name="username" required></div>
                        <div class="form-group"><label>비밀번호 *</label><input type="password" name="password" required minlength="6"></div>
                        <div class="form-group"><label>권한</label>
                            <select name="role"><option value="viewer">Viewer</option><option value="operator">Operator</option><option value="admin">Admin</option></select>
                        </div>
                        <div class="form-group"><label>이메일</label><input type="email" name="email"></div>
                    </div>
                    <button type="submit" class="btn btn-primary">생성</button>
                </form>
            </div>

            <div class="card">
                <h2>📋 사용자 목록</h2>
                <table>
                    <thead><tr><th>ID</th><th>사용자명</th><th>권한</th><th>이메일</th><th>상태</th><th>마지막 로그인</th><th>작업</th></tr></thead>
                    <tbody>
                    <?php foreach ($users as $u): ?>
                    <tr class="<?= $u['is_active'] ? '' : 'inactive' ?>">
                        <td><?= $u['id'] ?></td>
                        <td><?= htmlspecialchars($u['username']) ?></td>
                        <td><span class="role-badge role-<?= $u['role'] ?>"><?= strtoupper($u['role']) ?></span></td>
                        <td><?= htmlspecialchars($u['email'] ?: '-') ?></td>
                        <td><?= $u['is_active'] ? '✅ 활성' : '❌ 비활성' ?></td>
                        <td><?= $u['last_login'] ? date('Y-m-d H:i', strtotime($u['last_login'])) : '-' ?></td>
                        <td class="actions">
                            <?php if ($u['id'] != $user['id'] && $u['is_active']): ?>
                            <form method="post" style="display:flex;gap:5px;">
                                <input type="hidden" name="action" value="update_role"><input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                                <select name="role"><option value="viewer" <?= $u['role']=='viewer'?'selected':'' ?>>Viewer</option><option value="operator" <?= $u['role']=='operator'?'selected':'' ?>>Operator</option><option value="admin" <?= $u['role']=='admin'?'selected':'' ?>>Admin</option></select>
                                <button type="submit" class="btn btn-secondary">변경</button>
                            </form>
                            <form method="post" onsubmit="return confirm('정말 삭제하시겠습니까?')"><input type="hidden" name="action" value="delete"><input type="hidden" name="user_id" value="<?= $u['id'] ?>"><button class="btn btn-danger">삭제</button></form>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- 탭 2: Role별 권한 설정 -->
        <div id="tab-role_permissions" class="tab-content <?= $activeTab === 'role_permissions' ? 'active' : '' ?>">
            <div class="card">
                <h2>🔐 Role별 기본 권한 설정</h2>
                <p style="color:#666;font-size:13px;">각 Role이 기본적으로 가지는 메뉴 접근 및 기능 실행 권한을 설정합니다. Admin은 모든 권한이 항상 허용됩니다.</p>
                <table class="perm-table">
                    <thead>
                        <tr>
                            <th style="width:250px;">권한</th>
                            <th>Viewer</th>
                            <th>Demo</th>
                            <th>Operator</th>
                            <th>Admin</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr class="perm-group"><td colspan="5">📋 메뉴 접근 권한</td></tr>
                        <?php foreach ($permissionKeys as $key => $info): ?>
                            <?php if ($info['group'] === 'menu'): ?>
                            <tr>
                                <td><?= $info['label'] ?></td>
                                <?php foreach (['viewer', 'demo', 'operator', 'admin'] as $role): ?>
                                <td>
                                    <?php if ($role === 'admin'): ?>
                                        <span class="admin-locked">✅ 항상 허용</span>
                                    <?php else: ?>
                                        <form method="post" style="display:inline;">
                                            <input type="hidden" name="action" value="update_role_permission">
                                            <input type="hidden" name="role" value="<?= $role ?>">
                                            <input type="hidden" name="permission_key" value="<?= $key ?>">
                                            <input type="hidden" name="is_allowed" value="<?= ($allRolePermissions[$role][$key] ?? false) ? 0 : 1 ?>">
                                            <label class="toggle">
                                                <input type="checkbox" <?= ($allRolePermissions[$role][$key] ?? false) ? 'checked' : '' ?> onchange="this.form.submit()">
                                                <span class="toggle-slider"></span>
                                            </label>
                                        </form>
                                    <?php endif; ?>
                                </td>
                                <?php endforeach; ?>
                            </tr>
                            <?php endif; ?>
                        <?php endforeach; ?>
                        <tr class="perm-group"><td colspan="5">⚡ 기능 실행 권한</td></tr>
                        <?php foreach ($permissionKeys as $key => $info): ?>
                            <?php if ($info['group'] === 'action'): ?>
                            <tr>
                                <td><?= $info['label'] ?></td>
                                <?php foreach (['viewer', 'demo', 'operator', 'admin'] as $role): ?>
                                <td>
                                    <?php if ($role === 'admin'): ?>
                                        <span class="admin-locked">✅ 항상 허용</span>
                                    <?php else: ?>
                                        <form method="post" style="display:inline;">
                                            <input type="hidden" name="action" value="update_role_permission">
                                            <input type="hidden" name="role" value="<?= $role ?>">
                                            <input type="hidden" name="permission_key" value="<?= $key ?>">
                                            <input type="hidden" name="is_allowed" value="<?= ($allRolePermissions[$role][$key] ?? false) ? 0 : 1 ?>">
                                            <label class="toggle">
                                                <input type="checkbox" <?= ($allRolePermissions[$role][$key] ?? false) ? 'checked' : '' ?> onchange="this.form.submit()">
                                                <span class="toggle-slider"></span>
                                            </label>
                                        </form>
                                    <?php endif; ?>
                                </td>
                                <?php endforeach; ?>
                            </tr>
                            <?php endif; ?>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- 탭 3: 개별 사용자 권한 설정 -->
        <div id="tab-user_permissions" class="tab-content <?= $activeTab === 'user_permissions' ? 'active' : '' ?>">
            <div class="card">
                <h2>👤 개별 사용자 권한 오버라이드</h2>
                <p style="color:#666;font-size:13px;">특정 사용자에게 Role 기본 권한과 다른 권한을 부여합니다. 설정하지 않으면 Role 기본값이 적용됩니다.</p>

                <?php foreach ($users as $u): ?>
                <?php if ($u['is_active'] && $u['role'] !== 'admin'): ?>
                <?php $userPerms = getUserPermissions($conn, $u['id'], $u['role']); ?>
                <div style="margin-bottom:20px;padding:15px;background:#f8f9fa;border-radius:8px;">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
                        <h3 style="margin:0;">
                            <?= htmlspecialchars($u['username']) ?>
                            <span class="role-badge role-<?= $u['role'] ?>"><?= strtoupper($u['role']) ?></span>
                        </h3>
                        <form method="post" onsubmit="return confirm('이 사용자의 모든 개별 권한을 Role 기본값으로 초기화하시겠습니까?')">
                            <input type="hidden" name="action" value="reset_user_permissions">
                            <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                            <button type="submit" class="btn btn-warning" style="padding:5px 10px;font-size:12px;">🔄 Role 기본값으로 초기화</button>
                        </form>
                    </div>
                    <div style="display:flex;flex-wrap:wrap;gap:10px;">
                        <?php foreach ($permissionKeys as $key => $info): ?>
                        <div style="display:flex;align-items:center;gap:5px;background:white;padding:8px 12px;border-radius:4px;min-width:200px;">
                            <form method="post" style="display:flex;align-items:center;gap:8px;">
                                <input type="hidden" name="action" value="update_user_permission">
                                <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                                <input type="hidden" name="permission_key" value="<?= $key ?>">
                                <input type="hidden" name="is_allowed" value="<?= ($userPerms[$key] ?? false) ? 0 : 1 ?>">
                                <label class="toggle">
                                    <input type="checkbox" <?= ($userPerms[$key] ?? false) ? 'checked' : '' ?> onchange="this.form.submit()">
                                    <span class="toggle-slider"></span>
                                </label>
                                <span style="font-size:13px;"><?= $info['label'] ?></span>
                            </form>
                        </div>
                        <?php endforeach; ?>
                    </div>
                </div>
                <?php endif; ?>
                <?php endforeach; ?>
            </div>
        </div>
    </div>

    <script>
    function showTab(tabId) {
        document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.getElementById('tab-' + tabId).classList.add('active');
        event.target.classList.add('active');
        // URL 업데이트
        history.replaceState(null, '', '?tab=' + tabId);
    }
    </script>
</body>
</html>

