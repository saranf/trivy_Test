import json
import mysql.connector

# MySQL 연결 설정
db = mysql.connector.connect(
    host="localhost",
    user="trivy_user",
    password="trivy_password",
    database="trivy_db"
)

cursor = db.cursor()

# 테이블 생성 (필요 시)
cursor.execute("""
CREATE TABLE IF NOT EXISTS trivy_vulnerabilities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    library VARCHAR(255),
    vulnerability VARCHAR(255),
    severity VARCHAR(50),
    installed_version VARCHAR(50),
    fixed_version VARCHAR(50)
)
""")

# JSON 파일 읽기
with open("trivy-report.json") as f:
    data = json.load(f)

# 데이터 삽입
for vulnerability in data["Results"][0]["Vulnerabilities"]:
    cursor.execute("""
    INSERT INTO trivy_vulnerabilities (library, vulnerability, severity, installed_version, fixed_version)
    VALUES (%s, %s, %s, %s, %s)
    """, (
        vulnerability.get("PkgName"),
        vulnerability.get("VulnerabilityID"),
        vulnerability.get("Severity"),
        vulnerability.get("InstalledVersion"),
        vulnerability.get("FixedVersion")
    ))

db.commit()
cursor.close()
db.close()

