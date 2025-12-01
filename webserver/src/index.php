<?php
require_once 'auth.php';
$user = requireLogin();
$conn = getDbConnection();
initDatabase($conn);
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>Container Security Platform</title>
    <style>
        <?= getAuthStyles() ?>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; background: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; padding: 20px; }
        h1 { color: #333; text-align: center; margin-bottom: 30px; }
        .cards { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; }
        .card { background: white; padding: 25px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .card h2 { margin-top: 0; color: #007bff; font-size: 18px; }
        .card p { color: #666; font-size: 14px; margin-bottom: 15px; }
        button { padding: 10px 15px; font-size: 14px; border-radius: 4px; background: #007bff; color: white; border: none; cursor: pointer; }
        button:hover { background: #0056b3; }
        button:disabled { background: #ccc; }
        a.btn { display: inline-block; padding: 12px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 4px; font-size: 14px; }
        a.btn:hover { background: #0056b3; }
        a.btn.green { background: #28a745; }
        a.btn.green:hover { background: #1e7e34; }
        a.btn.purple { background: #6f42c1; }
        a.btn.purple:hover { background: #5a32a3; }
        a.btn.gray { background: #6c757d; }
        .status { margin-left: 10px; color: #666; font-size: 14px; }
        .disabled-card { opacity: 0.5; pointer-events: none; }
    </style>
</head>
<body>
    <?= getNavMenu() ?>
    <div class="container">
        <h1>🛡️ Container Security Platform</h1>

        <div class="cards">
            <!-- Viewer 이상 접근 가능 -->
            <div class="card">
                <h2>📋 Scan History</h2>
                <p>저장된 스캔 기록 확인 및 CSV 다운로드</p>
                <a href="./scan_history.php" class="btn green">스캔 기록</a>
            </div>

            <div class="card" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                <h2 style="color: white;">📊 Grafana Dashboard</h2>
                <p style="color: rgba(255,255,255,0.9);">전체 컨테이너 모니터링 및 취약점 현황 시각화</p>
                <a href="http://monitor.rmstudio.co.kr:3000/d/trivy-security/trivy-security-scanner?orgId=1" target="_blank" class="btn" style="background: white; color: #667eea;">대시보드 열기</a>
            </div>

            <!-- Operator 이상 접근 가능 -->
            <div class="card <?= isOperator() ? '' : 'disabled-card' ?>">
                <h2>🔍 Docker Container Scan</h2>
                <p>실행 중인 Docker 컨테이너를 선택하여 Trivy로 취약점 스캔</p>
                <?php if (isOperator()): ?>
                <a href="./container_scan.php" class="btn">컨테이너 스캔</a>
                <?php else: ?>
                <span class="btn gray">Operator 권한 필요</span>
                <?php endif; ?>
            </div>

            <div class="card <?= isOperator() ? '' : 'disabled-card' ?>">
                <h2>🛡️ 예외 처리 관리</h2>
                <p>오탐/비즈니스 사유로 기간 한정 예외 처리 관리</p>
                <?php if (isOperator()): ?>
                <a href="./exceptions.php" class="btn purple">예외 관리</a>
                <?php else: ?>
                <span class="btn gray">Operator 권한 필요</span>
                <?php endif; ?>
            </div>

            <div class="card <?= isOperator() ? '' : 'disabled-card' ?>">
                <h2>⚡ Auto Scan All</h2>
                <p>모든 실행 중인 컨테이너를 한번에 스캔</p>
                <?php if (isOperator()): ?>
                <button onclick="scanAll()" id="scanBtn">모든 컨테이너 스캔</button>
                <span id="status" class="status"></span>
                <?php else: ?>
                <span class="btn gray">Operator 권한 필요</span>
                <?php endif; ?>
            </div>

            <div class="card <?= isOperator() ? '' : 'disabled-card' ?>" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);">
                <h2 style="color: white;">📧 Diff 리포트</h2>
                <p style="color: rgba(255,255,255,0.9);">이전 스캔 대비 New/Fixed/Persistent 분석 및 이메일 발송</p>
                <?php if (isOperator()): ?>
                <a href="./send_diff_report.php" class="btn" style="background: white; color: #f5576c;">Diff 분석</a>
                <?php else: ?>
                <span class="btn gray" style="background: rgba(255,255,255,0.3); color: white;">Operator 권한 필요</span>
                <?php endif; ?>
            </div>

            <!-- Admin 전용 -->
            <?php if (isAdmin()): ?>
            <div class="card" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                <h2 style="color: white;">⏰ 주기적 스캔</h2>
                <p style="color: rgba(255,255,255,0.9);">특정 이미지를 정해진 주기로 자동 스캔</p>
                <a href="./scheduled_scans.php" class="btn" style="background: white; color: #667eea;">스케줄 설정</a>
            </div>

            <div class="card" style="background: #1a1a2e;">
                <h2 style="color: #ffc107;">⚙️ 관리자 메뉴</h2>
                <p style="color: rgba(255,255,255,0.7);">사용자 관리 및 시스템 감사 로그</p>
                <a href="./users.php" class="btn" style="background: #ffc107; color: #333;">👥 사용자 관리</a>
                <a href="./audit_logs.php" class="btn" style="background: #17a2b8; color: white; margin-left: 5px;">📜 감사 로그</a>
            </div>
            <?php endif; ?>
        </div>
    </div>

    <script>
        async function scanAll() {
            const btn = document.getElementById('scanBtn');
            const status = document.getElementById('status');
            btn.disabled = true;
            btn.textContent = 'Scanning...';
            status.textContent = '';
            try {
                const res = await fetch('./auto_scan.php?action=scan_all&skip_recent=0');
                const data = await res.json();
                if (data.success) {
                    const cnt = data.results.filter(r => r.status === 'scanned').length;
                    status.innerHTML = cnt + ' images scanned! <a href="./scan_monitor.php">View Diff</a>';
                } else {
                    status.textContent = 'Error: ' + data.message;
                }
            } catch (e) {
                status.textContent = 'Error: ' + e.message;
            }
            btn.disabled = false;
            btn.textContent = '모든 컨테이너 스캔';
        }
    </script>
</body>
</html>
