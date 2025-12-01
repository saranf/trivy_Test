<?php
require_once 'db_functions.php';

$conn = getDbConnection();
if ($conn) {
    initDatabase($conn);
}

// API 처리
$action = $_GET['action'] ?? '';

if ($action === 'delete' && isset($_GET['id'])) {
    deleteScan($conn, (int)$_GET['id']);
    header('Location: scan_history.php');
    exit;
}

if ($action === 'csv' && isset($_GET['id'])) {
    $scanId = (int)$_GET['id'];
    $vulns = getScanVulnerabilities($conn, $scanId);

    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename=scan_' . $scanId . '.csv');

    $output = fopen('php://output', 'w');
    // UTF-8 BOM for Excel compatibility
    fprintf($output, chr(0xEF).chr(0xBB).chr(0xBF));
    fputcsv($output, ['Library', 'Vulnerability ID', 'Severity', 'Installed Version', 'Fixed Version', 'Title'], ',', '"', '\\');
    foreach ($vulns as $v) {
        fputcsv($output, [$v['library'], $v['vulnerability'], $v['severity'], $v['installed_version'], $v['fixed_version'], $v['title']], ',', '"', '\\');
    }
    fclose($output);
    exit;
}

if ($action === 'detail' && isset($_GET['id'])) {
    header('Content-Type: application/json');
    echo json_encode(getScanVulnerabilities($conn, (int)$_GET['id']));
    exit;
}

$search = $_GET['search'] ?? '';
$sourceFilter = $_GET['source'] ?? '';
$history = $conn ? getScanHistory($conn, $search, $sourceFilter) : [];
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>스캔 기록</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { color: #333; }
        .back-link { margin-bottom: 20px; }
        .back-link a { color: #007bff; text-decoration: none; }
        table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); table-layout: fixed; }
        th, td { padding: 10px 8px; text-align: center; border-bottom: 1px solid #ddd; vertical-align: middle; overflow: hidden; text-overflow: ellipsis; }
        th { background: #f8f9fa; font-weight: 600; white-space: nowrap; }
        th:nth-child(1) { width: 40px; }  /* 체크박스 */
        th:nth-child(2) { width: 50px; }  /* ID */
        th:nth-child(3) { width: 60px; }  /* 소스 */
        th:nth-child(4) { width: auto; }  /* 이미지 */
        th:nth-child(5) { width: 140px; } /* 스캔일시 */
        th:nth-child(6) { width: 60px; }  /* 총취약점 */
        th:nth-child(7) { width: 70px; }  /* CRITICAL */
        th:nth-child(8) { width: 60px; }  /* HIGH */
        th:nth-child(9) { width: 70px; }  /* MEDIUM */
        th:nth-child(10) { width: 50px; } /* LOW */
        th:nth-child(11) { width: 160px; } /* 작업 */
        td:nth-child(4) { text-align: left; }
        tr:hover { background: #f5f5f5; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; color: white; min-width: 30px; }
        .critical { background: #dc3545; }
        .high { background: #fd7e14; }
        .medium { background: #ffc107; color: #333; }
        .low { background: #28a745; }
        .btn { display: inline-block; padding: 5px 10px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; font-size: 12px; margin: 2px; white-space: nowrap; }
        .btn-csv { background: #28a745; color: white; }
        .btn-delete { background: #dc3545; color: white; }
        .btn-detail { background: #007bff; color: white; }
        .no-data { text-align: center; padding: 40px; color: #666; }
        .tag { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; white-space: nowrap; }
        .tag-manual { background: #e3f2fd; color: #1565c0; }
        .tag-auto { background: #fff3e0; color: #e65100; }
        .tag-bulk { background: #f3e5f5; color: #7b1fa2; }
        .search-box { margin-bottom: 20px; display: flex; gap: 10px; align-items: center; flex-wrap: wrap; background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .search-box input[type="text"] { padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; width: 250px; }
        .search-box select { padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }
        .search-box button { padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .search-box a { padding: 10px 15px; background: #6c757d; color: white; border-radius: 4px; text-decoration: none; font-size: 14px; }
        .search-box .btn-email { margin-left: auto; padding: 10px 15px; }
        .btn-email { background: #6f42c1; color: white; }
        .checkbox-cell { width: 40px; text-align: center; }
        input[type="checkbox"] { width: 16px; height: 16px; cursor: pointer; }
        .email-modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; }
        .email-modal-content { background: white; margin: 100px auto; padding: 30px; border-radius: 8px; max-width: 500px; }
        .email-modal input[type="email"], .email-modal input[type="text"] { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; box-sizing: border-box; }
        .email-modal-buttons { display: flex; gap: 10px; justify-content: flex-end; margin-top: 20px; }
        .email-modal-buttons button { padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        .btn-send { background: #6f42c1; color: white; }
        .btn-cancel { background: #6c757d; color: white; }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; }
        .modal-content { background: white; margin: 50px auto; padding: 20px; border-radius: 8px; max-width: 90%; max-height: 80%; overflow: auto; }
        .modal-close { float: right; font-size: 24px; cursor: pointer; }
        .detail-table { font-size: 12px; }
        .actions-cell { white-space: nowrap; }
        #selected-count { font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="back-link"><a href="index.php">← 메인으로</a> | <a href="container_scan.php">컨테이너 스캔</a></div>
        <h1>📋 스캔 기록</h1>

        <div class="search-box">
            <form method="get" style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
                <input type="text" name="search" placeholder="이미지명 검색..." value="<?= htmlspecialchars($search) ?>">
                <select name="source">
                    <option value="">전체 소스</option>
                    <option value="manual" <?= $sourceFilter === 'manual' ? 'selected' : '' ?>>수동 스캔</option>
                    <option value="auto" <?= $sourceFilter === 'auto' ? 'selected' : '' ?>>자동 스캔</option>
                    <option value="bulk" <?= $sourceFilter === 'bulk' ? 'selected' : '' ?>>일괄 스캔</option>
                </select>
                <button type="submit">검색</button>
                <a href="scan_history.php">초기화</a>
            </form>
            <button class="btn btn-email" onclick="showEmailModal()">📧 선택 항목 메일 발송</button>
            <span id="selected-count"></span>
        </div>

        <?php if (empty($history)): ?>
            <div class="no-data">저장된 스캔 기록이 없습니다.</div>
        <?php else: ?>
            <table>
                <thead>
                    <tr>
                        <th class="checkbox-cell"><input type="checkbox" id="selectAll" onclick="toggleAll()"></th>
                        <th>ID</th>
                        <th>소스</th>
                        <th>이미지</th>
                        <th>스캔 일시</th>
                        <th>총 취약점</th>
                        <th>CRITICAL</th>
                        <th>HIGH</th>
                        <th>MEDIUM</th>
                        <th>LOW</th>
                        <th>작업</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($history as $h):
                        $source = $h['scan_source'] ?? 'manual';
                        $sourceLabel = ['manual' => '수동', 'auto' => '자동', 'bulk' => '일괄'][$source] ?? $source;
                        $tagClass = "tag-$source";
                    ?>
                    <tr>
                        <td><input type="checkbox" class="scan-check" value="<?= $h['id'] ?>" onchange="updateCount()"></td>
                        <td><?= $h['id'] ?></td>
                        <td><span class="tag <?= $tagClass ?>"><?= $sourceLabel ?></span></td>
                        <td title="<?= htmlspecialchars($h['image_name']) ?>"><?= htmlspecialchars($h['image_name']) ?></td>
                        <td><?= date('Y-m-d H:i', strtotime($h['scan_date'])) ?></td>
                        <td><strong><?= $h['total_vulns'] ?></strong></td>
                        <td><span class="badge critical"><?= $h['critical_count'] ?></span></td>
                        <td><span class="badge high"><?= $h['high_count'] ?></span></td>
                        <td><span class="badge medium"><?= $h['medium_count'] ?></span></td>
                        <td><span class="badge low"><?= $h['low_count'] ?></span></td>
                        <td class="actions-cell">
                            <button class="btn btn-detail" onclick="showDetail(<?= $h['id'] ?>)">상세</button>
                            <a href="?action=csv&id=<?= $h['id'] ?>" class="btn btn-csv">CSV</a>
                            <a href="?action=delete&id=<?= $h['id'] ?>" class="btn btn-delete" onclick="return confirm('삭제하시겠습니까?')">삭제</a>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>

    <div id="modal" class="modal">
        <div class="modal-content">
            <span class="modal-close" onclick="closeModal()">&times;</span>
            <h2>취약점 상세</h2>
            <div id="detail-content"></div>
        </div>
    </div>

    <!-- 이메일 발송 모달 -->
    <div id="emailModal" class="email-modal">
        <div class="email-modal-content">
            <h2>📧 스캔 결과 이메일 발송</h2>
            <p id="emailScanCount"></p>
            <input type="email" id="emailTo" placeholder="받는 사람 이메일" required>
            <input type="text" id="emailSubject" value="Trivy 스캔 결과 리포트" placeholder="제목">
            <div class="email-modal-buttons">
                <button class="btn-cancel" onclick="closeEmailModal()">취소</button>
                <button class="btn-send" onclick="sendEmail()">발송</button>
            </div>
            <div id="emailStatus" style="margin-top:15px;"></div>
        </div>
    </div>

    <script>
        function toggleAll() {
            const checked = document.getElementById('selectAll').checked;
            document.querySelectorAll('.scan-check').forEach(cb => cb.checked = checked);
            updateCount();
        }

        function updateCount() {
            const count = document.querySelectorAll('.scan-check:checked').length;
            document.getElementById('selected-count').textContent = count > 0 ? `${count}개 선택됨` : '';
        }

        function getSelectedIds() {
            return Array.from(document.querySelectorAll('.scan-check:checked')).map(cb => parseInt(cb.value));
        }

        function showEmailModal() {
            const ids = getSelectedIds();
            if (ids.length === 0) {
                alert('이메일로 발송할 스캔 기록을 선택하세요.');
                return;
            }
            document.getElementById('emailScanCount').textContent = `선택된 스캔: ${ids.length}개`;
            document.getElementById('emailStatus').textContent = '';
            document.getElementById('emailModal').style.display = 'block';
        }

        function closeEmailModal() {
            document.getElementById('emailModal').style.display = 'none';
        }

        async function sendEmail() {
            const ids = getSelectedIds();
            const email = document.getElementById('emailTo').value.trim();
            const subject = document.getElementById('emailSubject').value.trim();
            const status = document.getElementById('emailStatus');

            if (!email) {
                status.innerHTML = '<span style="color:red;">이메일 주소를 입력하세요.</span>';
                return;
            }

            status.innerHTML = '<span style="color:#666;">발송 중...</span>';

            try {
                const res = await fetch('send_email.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ scan_ids: ids, email: email, subject: subject })
                });
                const result = await res.json();

                if (result.success) {
                    status.innerHTML = '<span style="color:green;">✅ ' + result.message + '</span>';
                    setTimeout(closeEmailModal, 2000);
                } else {
                    status.innerHTML = '<span style="color:red;">❌ ' + result.message + '</span>';
                }
            } catch (e) {
                status.innerHTML = '<span style="color:red;">❌ 오류: ' + e.message + '</span>';
            }
        }

        async function showDetail(scanId) {
            const res = await fetch('?action=detail&id=' + scanId);
            const data = await res.json();

            let html = '<table class="detail-table"><thead><tr><th>Library</th><th>Vulnerability</th><th>Severity</th><th>Installed</th><th>Fixed</th><th>Title</th></tr></thead><tbody>';
            data.forEach(v => {
                const badgeClass = v.severity.toLowerCase();
                html += `<tr><td>${v.library}</td><td>${v.vulnerability}</td><td><span class="badge ${badgeClass}">${v.severity}</span></td><td>${v.installed_version}</td><td>${v.fixed_version || '-'}</td><td>${v.title || '-'}</td></tr>`;
            });
            html += '</tbody></table>';

            document.getElementById('detail-content').innerHTML = html;
            document.getElementById('modal').style.display = 'block';
        }

        function closeModal() {
            document.getElementById('modal').style.display = 'none';
        }

        window.onclick = function(e) {
            if (e.target == document.getElementById('modal')) closeModal();
            if (e.target == document.getElementById('emailModal')) closeEmailModal();
        }
    </script>
</body>
</html>
