import subprocess
import sys
import os

def run_command(command, description):
    """Run a shell command and print its status"""
    print(f"\n📝 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, 
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"✅ Success: {description}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed: {description}")
        print(f"Error: {e.stderr.decode()}")
        return False

def setup_target():
    """Setup target with required services"""
    print("\n🔧 Starting target setup...\n")
    
    # Check if running as root
    if os.geteuid() != 0:
        print("❌ This script must be run as root!")
        sys.exit(1)

    # Install required packages
    packages = [
        "apache2",          # Web server
        "php",             # PHP for web applications
        "mysql-server",    # MySQL database
        "openssh-server",  # SSH server
        "vsftpd",         # FTP server
        "ufw"             # Firewall
    ]
    
    print("📦 Installing required packages...")
    for package in packages:
        run_command(f"apt-get install -y {package}", f"Installing {package}")

    # Configure Apache
    run_command("systemctl start apache2", "Starting Apache web server")
    run_command("systemctl enable apache2", "Enabling Apache web server")
    
    # Create test web application
    webroot = "/var/www/html"
    run_command(f"rm {webroot}/index.html", "Removing default index.html")
    
    # Create login page for SQL injection testing
    with open(f"{webroot}/login.php", "w") as f:
        f.write("""
<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST["username"];
    $password = $_POST["password"];
    // Vulnerable SQL query for testing
    $query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
}
?>
<html>
<head><title>Login Page</title></head>
<body>
    <h2>Login</h2>
    <form method="post">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>
        """)
    
    # Create admin directory for enumeration testing
    run_command(f"mkdir -p {webroot}/admin", "Creating admin directory")
    with open(f"{webroot}/admin/index.html", "w") as f:
        f.write("<html><body><h1>Admin Panel</h1></body></html>")

    # Configure MySQL
    run_command("systemctl start mysql", "Starting MySQL server")
    run_command("systemctl enable mysql", "Enabling MySQL server")
    
    # Configure SSH
    run_command("systemctl start ssh", "Starting SSH server")
    run_command("systemctl enable ssh", "Enabling SSH server")
    
    # Configure FTP
    run_command("systemctl start vsftpd", "Starting FTP server")
    run_command("systemctl enable vsftpd", "Enabling FTP server")
    
    # Configure firewall
    run_command("ufw allow 80/tcp", "Allowing HTTP traffic")
    run_command("ufw allow 443/tcp", "Allowing HTTPS traffic")
    run_command("ufw allow 22/tcp", "Allowing SSH traffic")
    run_command("ufw allow 21/tcp", "Allowing FTP traffic")
    run_command("ufw allow 3306/tcp", "Allowing MySQL traffic")
    
    # Create test database and user
    mysql_commands = """
    CREATE DATABASE IF NOT EXISTS testdb;
    CREATE TABLE IF NOT EXISTS testdb.users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50),
        password VARCHAR(50)
    );
    INSERT INTO testdb.users (username, password) VALUES ('admin', 'password123');
    """
    
    with open("/tmp/mysql_setup.sql", "w") as f:
        f.write(mysql_commands)
    
    run_command("mysql < /tmp/mysql_setup.sql", "Setting up test database")
    
    print("\n✅ Target setup completed!")
    print("\n📋 Services configured:")
    print("- Web server (Apache) - Port 80")
    print("- MySQL Database - Port 3306")
    print("- SSH Server - Port 22")
    print("- FTP Server - Port 21")
    
    print("\n🔍 Test pages created:")
    print("- Login page: http://localhost/login.php")
    print("- Admin panel: http://localhost/admin/")
    
    print("\n⚠️ Warning: This configuration is intentionally vulnerable for testing!")
    print("Do not use on production systems or expose to the internet.")

if __name__ == "__main__":
    setup_target() 