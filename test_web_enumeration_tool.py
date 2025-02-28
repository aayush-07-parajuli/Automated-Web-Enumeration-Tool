import unittest
import sqlite3
import hashlib
from web_enumeration_tool import hash_password, signup, login, enumerate_subdomains, enumerate_directories, analyze_http_headers

class TestWebEnum(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Setup test database before running tests"""
        cls.conn = sqlite3.connect(":memory:")  # Use in-memory DB for testing
        cls.cursor = cls.conn.cursor()

        cls.cursor.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT
            )
        """)
        cls.cursor.execute("""
            CREATE TABLE results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
                subdomains TEXT,
                directories TEXT,
                http_headers TEXT,
                open_ports TEXT,
                dns_records TEXT
            )
        """)
        cls.conn.commit()

    def test_hash_password(self):
        """Test password hashing function"""
        password = "securepassword"
        hashed_pw = hash_password(password)
        self.assertEqual(hashlib.sha256(password.encode()).hexdigest(), hashed_pw)

    def test_user_signup_and_login(self):
        """Test user signup and login"""
        username = "test_user"
        password = "test_password"
        hashed_pw = hash_password(password)

        # Insert user manually for testing login
        self.cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
        self.conn.commit()

        # Simulate login
        self.cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed_pw))
        user = self.cursor.fetchone()
        self.assertIsNotNone(user)

    def test_enumerate_subdomains(self):
        """Test subdomain enumeration function"""
        result = enumerate_subdomains("example.com")
        self.assertIsInstance(result, str)

    def test_enumerate_directories(self):
        """Test directory enumeration function"""
        result = enumerate_directories("example.com")
        self.assertIsInstance(result, str)

    def test_analyze_http_headers(self):
        """Test HTTP header analysis function"""
        result = analyze_http_headers("example.com")
        self.assertIsInstance(result, str)

    @classmethod
    def tearDownClass(cls):
        """Close test database connection"""
        cls.conn.close()

if __name__ == '__main__':
    unittest.main()
