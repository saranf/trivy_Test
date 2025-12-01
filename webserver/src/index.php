<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>Trivy Security Scanner</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 900px; margin: 0 auto; }
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
        .status { margin-left: 10px; color: #666; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Trivy Security Scanner</h1>

        <div class="cards">
            <div class="card">
                <h2>Docker Container Scan</h2>
                <p>실행 중인 Docker 컨테이너를 선택하여 Trivy로 취약점 스캔</p>
                <a href="./container_scan.php" class="btn">컨테이너 스캔</a>
            </div>

            <div class="card">
                <h2>Scan History</h2>
                <p>저장된 스캔 기록 확인 및 CSV 다운로드</p>
                <a href="./scan_history.php" class="btn green">스캔 기록</a>
            </div>

            <div class="card">
                <h2>🛡️ 예외 처리 관리</h2>
                <p>오탐/비즈니스 사유로 기간 한정 예외 처리 관리</p>
                <a href="./exceptions.php" class="btn purple">예외 관리</a>
            </div>

            <div class="card">
                <h2>Auto Scan All</h2>
                <p>모든 실행 중인 컨테이너를 한번에 스캔</p>
                <button onclick="scanAll()" id="scanBtn">모든 컨테이너 스캔</button>
                <span id="status" class="status"></span>
            </div>

            <div class="card" style="grid-column: span 2; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                <h2 style="color: white;">📊 Grafana Dashboard</h2>
                <p style="color: rgba(255,255,255,0.9);">전체 컨테이너 모니터링 및 취약점 현황 시각화</p>
                <a href="http://monitor.rmstudio.co.kr:3000/d/trivy-security/trivy-security-scanner?orgId=1" target="_blank" class="btn" style="background: white; color: #667eea;">전체 대시보드 열기</a>
            </div>
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
