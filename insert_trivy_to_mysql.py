db = mysql.connector.connect(
    host="mysql",  # docker-compose에서 정의한 서비스 이름
    user="trivy_user",
    password="trivy_password",
    database="trivy_db"
)

