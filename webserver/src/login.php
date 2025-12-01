<?php
session_start();
require_once 'db_functions.php';

// 이미 로그인된 경우 메인으로 리다이렉트
if (isset($_SESSION['user'])) {
    header('Location: index.php');
    exit;
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $conn = getDbConnection();
    if ($conn) {
        initDatabase($conn);
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        if (empty($username) || empty($password)) {
            $error = '사용자명과 비밀번호를 입력하세요.';
        } else {
            $result = authenticateUser($conn, $username, $password);
            if ($result['success']) {
                $_SESSION['user'] = $result['user'];
                logAudit($conn, $result['user']['id'], $username, 'LOGIN', 'user', $result['user']['id'], null);
                header('Location: index.php');
                exit;
            } else {
                $error = $result['error'];
            }
        }
        $conn->close();
    } else {
        $error = '데이터베이스 연결 실패';
    }
}
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>로그인 - Container Security Platform</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0; padding: 0;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex; align-items: center; justify-content: center;
        }
        .login-container {
            background: white; border-radius: 12px; padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            width: 100%; max-width: 400px;
        }
        .logo { text-align: center; margin-bottom: 30px; }
        .logo h1 { margin: 0; font-size: 24px; color: #1a1a2e; }
        .logo p { margin: 5px 0 0; color: #666; font-size: 14px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; font-weight: 600; color: #333; }
        .form-group input {
            width: 100%; padding: 12px 15px; border: 2px solid #e0e0e0;
            border-radius: 8px; font-size: 14px; transition: border-color 0.3s;
        }
        .form-group input:focus { outline: none; border-color: #007bff; }
        .btn-login {
            width: 100%; padding: 14px; background: #007bff; color: white;
            border: none; border-radius: 8px; font-size: 16px; font-weight: 600;
            cursor: pointer; transition: background 0.3s;
        }
        .btn-login:hover { background: #0056b3; }
        .error-msg { background: #fff0f0; color: #dc3545; padding: 12px; border-radius: 8px;
            margin-bottom: 20px; font-size: 14px; text-align: center; }
        .role-info { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; }
        .role-info h3 { font-size: 14px; color: #666; margin: 0 0 15px; }
        .role-badge { display: inline-block; padding: 4px 10px; border-radius: 12px;
            font-size: 11px; font-weight: bold; margin-right: 5px; }
        .role-admin { background: #dc3545; color: white; }
        .role-operator { background: #28a745; color: white; }
        .role-viewer { background: #6c757d; color: white; }
        .role-demo { background: #9c27b0; color: white; }
        .role-desc { font-size: 12px; color: #888; margin-top: 10px; }
        .demo-box { background: linear-gradient(135deg, #9c27b0 0%, #673ab7 100%); color: white; padding: 15px; border-radius: 8px; margin-top: 20px; }
        .demo-box h4 { margin: 0 0 10px; font-size: 14px; }
        .demo-box p { margin: 0; font-size: 12px; line-height: 1.6; }
        .demo-box code { background: rgba(255,255,255,0.2); padding: 2px 6px; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>🛡️ Container Security</h1>
            <p>Automated Security Operations Platform</p>
        </div>

        <?php if ($error): ?>
        <div class="error-msg"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <form method="post">
            <div class="form-group">
                <label for="username">사용자명</label>
                <input type="text" id="username" name="username" required autocomplete="username">
            </div>
            <div class="form-group">
                <label for="password">비밀번호</label>
                <input type="password" id="password" name="password" required autocomplete="current-password">
            </div>
            <button type="submit" class="btn-login">로그인</button>
        </form>

        <div class="demo-box">
            <h4>🎓 면접관 체험 모드</h4>
            <p>
                모든 기능을 안전하게 체험해 보세요!<br>
                계정: <code>demo</code> / 비밀번호: <code>demo123</code><br>
                <small>(실제 데이터는 마스킹되며, 저장/메일 발송은 시뮬레이션됩니다)</small>
            </p>
        </div>

        <div class="role-info">
            <h3>사용자 권한 안내</h3>
            <span class="role-badge role-admin">Admin</span>
            <span class="role-badge role-operator">Operator</span>
            <span class="role-badge role-demo">Demo</span>
            <span class="role-badge role-viewer">Viewer</span>
            <p class="role-desc">
                <strong>Viewer</strong>: 대시보드 조회<br>
                <strong>Demo</strong>: 기능 체험 (저장/발송 시뮬레이션)<br>
                <strong>Operator</strong>: 스캔 실행, 예외 처리<br>
                <strong>Admin</strong>: 사용자/시스템 관리
            </p>
        </div>
    </div>
</body>
</html>

