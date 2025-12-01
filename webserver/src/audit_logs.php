<?php
require_once 'auth.php';
$user = requireRole('admin');
$conn = getDbConnection();
initDatabase($conn);

// 필터 파라미터
$filters = [
    'action' => $_GET['action_filter'] ?? '',
    'date_from' => $_GET['date_from'] ?? '',
    'date_to' => $_GET['date_to'] ?? ''
];
$limit = (int)($_GET['limit'] ?? 100);

$logs = getAuditLogs($conn, $limit, $filters);

// 액션 타입 목록
$actionTypes = [];
$result = $conn->query("SELECT DISTINCT action FROM audit_logs ORDER BY action");
while ($row = $result->fetch_assoc()) {
    $actionTypes[] = $row['action'];
}
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>감사 로그 - Container Security</title>
    <style>
        <?= getAuthStyles() ?>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        h1 { color: #333; }
        .filter-box { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); display: flex; gap: 15px; flex-wrap: wrap; align-items: end; }
        .filter-group { display: flex; flex-direction: column; gap: 5px; }
        .filter-group label { font-size: 12px; font-weight: 600; color: #666; }
        .filter-group input, .filter-group select { padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }
        .btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; }
        .btn-primary { background: #007bff; color: white; }
        .btn-secondary { background: #6c757d; color: white; }
        table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #eee; font-size: 13px; }
        th { background: #f8f9fa; font-weight: 600; position: sticky; top: 0; }
        tr:hover { background: #f8f9fa; }
        .action-badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }
        .action-login { background: #d4edda; color: #155724; }
        .action-logout { background: #f8d7da; color: #721c24; }
        .action-scan { background: #cce5ff; color: #004085; }
        .action-exception { background: #fff3cd; color: #856404; }
        .action-user { background: #e2e3e5; color: #383d41; }
        .details { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #666; }
        .no-data { text-align: center; padding: 40px; color: #666; }
        .stats { display: flex; gap: 20px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 15px 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat-card .number { font-size: 24px; font-weight: bold; color: #333; }
        .stat-card .label { font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <?= getNavMenu() ?>
    <div class="container">
        <h1>📜 감사 로그</h1>

        <div class="stats">
            <div class="stat-card"><div class="number"><?= count($logs) ?></div><div class="label">조회된 로그</div></div>
        </div>

        <form class="filter-box" method="get">
            <div class="filter-group">
                <label>액션 유형</label>
                <select name="action_filter">
                    <option value="">전체</option>
                    <?php foreach ($actionTypes as $at): ?>
                    <option value="<?= $at ?>" <?= $filters['action'] == $at ? 'selected' : '' ?>><?= $at ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="filter-group">
                <label>시작일</label>
                <input type="date" name="date_from" value="<?= htmlspecialchars($filters['date_from']) ?>">
            </div>
            <div class="filter-group">
                <label>종료일</label>
                <input type="date" name="date_to" value="<?= htmlspecialchars($filters['date_to']) ?>">
            </div>
            <div class="filter-group">
                <label>표시 개수</label>
                <select name="limit">
                    <option value="50" <?= $limit == 50 ? 'selected' : '' ?>>50</option>
                    <option value="100" <?= $limit == 100 ? 'selected' : '' ?>>100</option>
                    <option value="500" <?= $limit == 500 ? 'selected' : '' ?>>500</option>
                </select>
            </div>
            <button type="submit" class="btn btn-primary">필터 적용</button>
            <a href="audit_logs.php" class="btn btn-secondary">초기화</a>
        </form>

        <table>
            <thead>
                <tr><th>시간</th><th>사용자</th><th>액션</th><th>대상</th><th>상세</th><th>IP</th></tr>
            </thead>
            <tbody>
                <?php if (empty($logs)): ?>
                <tr><td colspan="6" class="no-data">로그가 없습니다.</td></tr>
                <?php else: ?>
                <?php foreach ($logs as $log): ?>
                <?php
                    $actionClass = 'action-user';
                    if (strpos($log['action'], 'LOGIN') !== false || strpos($log['action'], 'LOGOUT') !== false) $actionClass = $log['action'] == 'LOGIN' ? 'action-login' : 'action-logout';
                    elseif (strpos($log['action'], 'SCAN') !== false) $actionClass = 'action-scan';
                    elseif (strpos($log['action'], 'EXCEPTION') !== false) $actionClass = 'action-exception';
                ?>
                <tr>
                    <td><?= date('Y-m-d H:i:s', strtotime($log['created_at'])) ?></td>
                    <td><?= htmlspecialchars($log['username'] ?? '-') ?></td>
                    <td><span class="action-badge <?= $actionClass ?>"><?= htmlspecialchars($log['action']) ?></span></td>
                    <td><?= htmlspecialchars(($log['target_type'] ?? '') . ($log['target_id'] ? ':' . $log['target_id'] : '')) ?></td>
                    <td class="details" title="<?= htmlspecialchars($log['details'] ?? '') ?>"><?= htmlspecialchars($log['details'] ?? '-') ?></td>
                    <td><?= htmlspecialchars($log['ip_address'] ?? '-') ?></td>
                </tr>
                <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
</body>
</html>

