import mysql.connector  # mysql.connector 모듈을 불러옵니다.
import json

# MySQL 데이터베이스에 연결
db = mysql.connector.connect(
    host="mysql",  # Docker Compose에서 정의한 MySQL 서비스 이름
    user="trivy_user",
    password="trivy_password",
    database="trivy_db"
)

# JSON 파일에서 Trivy 스캔 데이터를 읽어서 데이터베이스에 삽입
cursor = db.cursor()
with open('trivy-report.json', 'r') as f:
    data = json.load(f)
    for vuln in data.get('Vulnerabilities', []):
        query = """
        INSERT INTO trivy_vulnerabilities (Library, Vulnerability, Severity, InstalledVersion, FixedVersion)
        VALUES (%s, %s, %s, %s, %s)
        """
        values = (
            vuln.get('Library', 'N/A'),
            vuln.get('VulnerabilityID', 'N/A'),
            vuln.get('Severity', 'N/A'),
            vuln.get('InstalledVersion', 'N/A'),
            vuln.get('FixedVersion', 'N/A')
        )
        cursor.execute(query, values)

db.commit()
cursor.close()
db.close()

