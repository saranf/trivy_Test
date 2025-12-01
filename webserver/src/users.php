<?php
require_once 'auth.php';
$user = requireRole('admin');
$conn = getDbConnection();
initDatabase($conn);

$message = '';
$error = '';

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
    }
}

$users = getUsers($conn);
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
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
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
    </style>
</head>
<body>
    <?= getNavMenu() ?>
    <div class="container">
        <h1>👥 사용자 관리</h1>

        <?php if ($message): ?><div class="message success"><?= htmlspecialchars($message) ?></div><?php endif; ?>
        <?php if ($error): ?><div class="message error"><?= htmlspecialchars($error) ?></div><?php endif; ?>

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
</body>
</html>

