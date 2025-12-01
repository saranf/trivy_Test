<?php
require_once 'auth.php';
$user = requireRole('operator');  // Operator 이상만 접근 가능

$conn = getDbConnection();
if ($conn) {
    initDatabase($conn);
}

// 삭제 처리 (데모 모드에서는 실제 삭제 안함)
if (isset($_GET['action']) && $_GET['action'] === 'delete' && isset($_GET['id'])) {
    if (!isDemoMode()) {
        deleteException($conn, (int)$_GET['id']);
        auditLog($conn, 'DELETE_EXCEPTION', 'exception', $_GET['id'], null);
    }
    header('Location: exceptions.php');
    exit;
}

$exceptions = $conn ? getAllExceptions($conn) : [];
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>예외 처리 관리</title>
    <style>
        <?= getAuthStyles() ?>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1 { color: #333; }
        .info-box { background: #e3f2fd; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #1976d2; }
        table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; font-weight: 600; }
        tr:hover { background: #f5f5f5; }
        .status { display: inline-block; padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; }
        .status-active { background: #d4edda; color: #155724; }
        .status-expired { background: #fff3cd; color: #856404; }
        .status-deleted { background: #f8d7da; color: #721c24; }
        .btn { padding: 6px 12px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; font-size: 12px; }
        .btn-delete { background: #dc3545; color: white; }
        .no-data { text-align: center; padding: 40px; color: #666; background: white; border-radius: 8px; }
        .expires-soon { color: #fd7e14; font-weight: bold; }
    </style>
</head>
<body>
    <?= getNavMenu() ?>
    <?= getDemoBanner() ?>
    <div class="container">
        <h1>🛡️ 예외 처리 관리 (Risk Acceptance)</h1>
        
        <div class="info-box">
            <strong>📋 예외 처리란?</strong><br>
            오탐(False Positive)이나 비즈니스 사유로 당장 패치할 수 없는 취약점을 <strong>기간 한정</strong>으로 예외 처리합니다.<br>
            만료일이 지나면 자동으로 다시 취약점 목록에 표시되어 재검토할 수 있습니다.
        </div>

        <?php if (empty($exceptions)): ?>
            <div class="no-data">
                등록된 예외 처리가 없습니다.<br><br>
                스캔 기록의 상세 보기에서 취약점별로 예외 처리를 등록할 수 있습니다.
            </div>
        <?php else: ?>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>취약점 ID</th>
                        <th>이미지 패턴</th>
                        <th>사유</th>
                        <th>등록일</th>
                        <th>만료일</th>
                        <th>상태</th>
                        <th>작업</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($exceptions as $e): 
                        $statusClass = 'status-' . $e['status'];
                        $statusLabel = ['active' => '활성', 'expired' => '만료', 'deleted' => '삭제'][$e['status']] ?? $e['status'];
                        
                        // 만료 임박 체크 (7일 이내)
                        $expiresAt = strtotime($e['expires_at']);
                        $daysLeft = ceil(($expiresAt - time()) / 86400);
                        $expiresSoon = $e['status'] === 'active' && $daysLeft <= 7 && $daysLeft > 0;
                    ?>
                    <tr>
                        <td><?= $e['id'] ?></td>
                        <td><code><?= htmlspecialchars($e['vulnerability_id']) ?></code></td>
                        <td><?= htmlspecialchars($e['image_pattern']) ?></td>
                        <td><?= htmlspecialchars($e['reason']) ?></td>
                        <td><?= date('Y-m-d', strtotime($e['created_at'])) ?></td>
                        <td class="<?= $expiresSoon ? 'expires-soon' : '' ?>">
                            <?= date('Y-m-d', strtotime($e['expires_at'])) ?>
                            <?php if ($expiresSoon): ?>
                                <br><small>(<?= $daysLeft ?>일 남음)</small>
                            <?php endif; ?>
                        </td>
                        <td><span class="status <?= $statusClass ?>"><?= $statusLabel ?></span></td>
                        <td>
                            <?php if ($e['status'] === 'active'): ?>
                                <a href="?action=delete&id=<?= $e['id'] ?>" class="btn btn-delete" onclick="return confirm('예외 처리를 삭제하시겠습니까?')">삭제</a>
                            <?php else: ?>
                                -
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</body>
</html>

