<?php
/**
 * 주기적 스캔 설정 (Admin 전용)
 */
require_once 'auth.php';
$user = requireRole('admin');

require_once 'db_functions.php';

$conn = getDbConnection();
if ($conn) {
    initDatabase($conn);
}

// 삭제 처리
if (isset($_GET['delete']) && is_numeric($_GET['delete'])) {
    deleteScheduledScan($conn, (int)$_GET['delete']);
    auditLog($conn, 'DELETE_SCHEDULED_SCAN', 'scheduled_scan', $_GET['delete'], null);
    header('Location: scheduled_scans.php');
    exit;
}

// 활성화/비활성화 토글
if (isset($_GET['toggle']) && is_numeric($_GET['toggle'])) {
    $id = (int)$_GET['toggle'];
    $conn->query("UPDATE scheduled_scans SET is_active = NOT is_active WHERE id = $id");
    auditLog($conn, 'TOGGLE_SCHEDULED_SCAN', 'scheduled_scan', $id, null);
    header('Location: scheduled_scans.php');
    exit;
}

// 추가/수정 처리
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $imageName = trim($_POST['image_name'] ?? '');
    $scheduleType = $_POST['schedule_type'] ?? 'daily';
    $scheduleTime = $_POST['schedule_time'] ?? '02:00';
    $scheduleDay = (int)($_POST['schedule_day'] ?? 0);
    $editId = (int)($_POST['edit_id'] ?? 0);

    if (!empty($imageName)) {
        if ($editId > 0) {
            $isActive = isset($_POST['is_active']) ? 1 : 0;
            updateScheduledScan($conn, $editId, $imageName, $scheduleType, $scheduleTime, $scheduleDay, $isActive);
            auditLog($conn, 'UPDATE_SCHEDULED_SCAN', 'scheduled_scan', $editId, "image: {$imageName}");
        } else {
            $id = addScheduledScan($conn, $imageName, $scheduleType, $scheduleTime, $scheduleDay, $user['id']);
            auditLog($conn, 'ADD_SCHEDULED_SCAN', 'scheduled_scan', $id, "image: {$imageName}");
        }
    }
    header('Location: scheduled_scans.php');
    exit;
}

$scheduledScans = getScheduledScans($conn, false);
$dayNames = ['일', '월', '화', '수', '목', '금', '토'];
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>주기적 스캔 설정</title>
    <style>
        <?= getAuthStyles() ?>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .card { background: white; padding: 25px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        h1 { color: #333; margin-bottom: 5px; }
        .subtitle { color: #666; margin-bottom: 20px; }
        .form-row { display: flex; gap: 15px; flex-wrap: wrap; align-items: flex-end; margin-bottom: 15px; }
        .form-group { flex: 1; min-width: 150px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: 600; color: #333; font-size: 13px; }
        .form-group input, .form-group select { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }
        .btn { padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; text-decoration: none; display: inline-block; }
        .btn-primary { background: #007bff; color: white; }
        .btn-danger { background: #dc3545; color: white; }
        .btn-success { background: #28a745; color: white; }
        .btn-secondary { background: #6c757d; color: white; }
        .btn-sm { padding: 5px 10px; font-size: 12px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; border-bottom: 1px solid #ddd; text-align: left; }
        th { background: #f8f9fa; font-weight: 600; }
        .status-active { color: #28a745; }
        .status-inactive { color: #6c757d; }
        .badge { padding: 3px 8px; border-radius: 12px; font-size: 11px; color: white; }
        .badge-hourly { background: #17a2b8; }
        .badge-daily { background: #28a745; }
        .badge-weekly { background: #6f42c1; }
        .info-box { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .info-box h2 { margin: 0 0 10px 0; }
        .day-select { display: none; }
        .day-select.show { display: block; }
    </style>
</head>
<body>
    <?= getNavMenu() ?>
    <div class="container">
        <div class="info-box">
            <h2>⏰ 주기적 스캔 설정</h2>
            <p>특정 컨테이너/이미지를 정해진 주기로 자동 스캔하고 결과를 MySQL에 저장합니다.</p>
        </div>

        <div class="card">
            <h3>➕ 새 스케줄 추가</h3>
            <form method="post">
                <div class="form-row">
                    <div class="form-group" style="flex: 2;">
                        <label>이미지명 (Docker 이미지 또는 컨테이너명)</label>
                        <input type="text" name="image_name" placeholder="nginx:latest 또는 my_container" required>
                    </div>
                    <div class="form-group">
                        <label>스캔 주기</label>
                        <select name="schedule_type" id="scheduleType" onchange="toggleDaySelect()">
                            <option value="hourly">매시간</option>
                            <option value="daily" selected>매일</option>
                            <option value="weekly">매주</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>시간</label>
                        <input type="time" name="schedule_time" value="02:00">
                    </div>
                    <div class="form-group day-select" id="daySelect">
                        <label>요일</label>
                        <select name="schedule_day">
                            <?php for ($i = 0; $i < 7; $i++): ?>
                            <option value="<?= $i ?>"><?= $dayNames[$i] ?>요일</option>
                            <?php endfor; ?>
                        </select>
                    </div>
                    <div class="form-group" style="flex: 0;">
                        <label>&nbsp;</label>
                        <button type="submit" class="btn btn-primary">추가</button>
                    </div>
                </div>
            </form>
        </div>

        <div class="card">
            <h3>📋 등록된 스케줄</h3>
            <?php if (empty($scheduledScans)): ?>
            <p style="color: #666; text-align: center;">등록된 주기적 스캔이 없습니다.</p>
            <?php else: ?>
            <table>
                <thead>
                    <tr>
                        <th>상태</th>
                        <th>이미지</th>
                        <th>주기</th>
                        <th>시간</th>
                        <th>마지막 실행</th>
                        <th>다음 실행</th>
                        <th>생성자</th>
                        <th>관리</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($scheduledScans as $s): ?>
                    <tr>
                        <td>
                            <?php if ($s['is_active']): ?>
                            <span class="status-active">● 활성</span>
                            <?php else: ?>
                            <span class="status-inactive">○ 비활성</span>
                            <?php endif; ?>
                        </td>
                        <td><strong><?= htmlspecialchars($s['image_name']) ?></strong></td>
                        <td><span class="badge badge-<?= $s['schedule_type'] ?>"><?= $s['schedule_type'] ?></span></td>
                        <td>
                            <?= substr($s['schedule_time'], 0, 5) ?>
                            <?php if ($s['schedule_type'] === 'weekly'): ?>
                            (<?= $dayNames[$s['schedule_day']] ?>)
                            <?php endif; ?>
                        </td>
                        <td><?= $s['last_run'] ? date('m/d H:i', strtotime($s['last_run'])) : '-' ?></td>
                        <td><?= $s['next_run'] ? date('m/d H:i', strtotime($s['next_run'])) : '-' ?></td>
                        <td><?= htmlspecialchars($s['created_by_name'] ?? '-') ?></td>
                        <td>
                            <a href="?toggle=<?= $s['id'] ?>" class="btn btn-sm <?= $s['is_active'] ? 'btn-secondary' : 'btn-success' ?>">
                                <?= $s['is_active'] ? '비활성화' : '활성화' ?>
                            </a>
                            <a href="?delete=<?= $s['id'] ?>" class="btn btn-sm btn-danger" onclick="return confirm('삭제하시겠습니까?')">삭제</a>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>
        </div>
    </div>
    <script>
    function toggleDaySelect() {
        const type = document.getElementById('scheduleType').value;
        document.getElementById('daySelect').classList.toggle('show', type === 'weekly');
    }
    </script>
</body>
</html>

