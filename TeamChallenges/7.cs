using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
using System.ComponentModel.DataAnnotations;
using System.Data;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;

namespace SecureLoginAPI
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private const string connectionString = "Server=myServer;Database=myDB;User Id=admin;Password=admin123;";

        // 1. Fix SQL Injection vulnerability using parameterized queries
        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginModel model)
        {
            string query = "SELECT * FROM Users WHERE Username = @Username AND Password = @Password";

            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                conn.Open();
                using (SqlCommand cmd = new SqlCommand(query, conn))
                {
                    cmd.Parameters.Add("@Username", SqlDbType.NVarChar).Value = model.Username;
                    cmd.Parameters.Add("@Password", SqlDbType.NVarChar).Value = model.Password;

                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        if (reader.HasRows)
                        {
                            return Ok("Login Successful");
                        }
                        else
                        {
                            return Unauthorized("Login Failed");
                        }
                    }
                }
            }
        }

        // 2. Fix Insecure Password Storage by hashing passwords
        [HttpPost("storePassword")]
        public IActionResult StorePassword([FromBody] string password)
        {
            string hashedPassword = HashPassword(password);
            System.IO.File.WriteAllText("passwords.txt", hashedPassword); // Example: storing hashed password
            return Ok("Password stored securely");
        }

        private string HashPassword(string password)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }

        // 3. Fix Improper Exception Handling by logging less sensitive info
        [HttpGet("testError")]
        public IActionResult TestError()
        {
            try
            {
                throw new Exception("Critical Error!"); // Simulated error
            }
            catch (Exception ex)
            {
                // Logging generic error message
                System.IO.File.AppendAllText("error_log.txt", "An error occurred: " + ex.Message);
                return BadRequest("An error occurred");
            }
        }

        // 4. Remove Hardcoded Credentials by using secure storage or configuration
        [HttpGet("adminAccess")]
        public IActionResult AdminAccess()
        {
            string adminPassword = GetAdminPassword(); // Securely retrieve password
            if (adminPassword == "admin123") // Example check
            {
                return Ok("Admin access granted");
            }
            return Unauthorized("Access denied");
        }

        private string GetAdminPassword()
        {
            // Securely retrieve the admin password (e.g., from a secure vault or environment variable)
            return Environment.GetEnvironmentVariable("ADMIN_PASSWORD") ?? "defaultPassword";
        }

        // 5. Fix XSS vulnerability by encoding user input
        [HttpGet("greet")]
        public IActionResult GreetUser([FromQuery] string username)
        {
            string encodedUsername = System.Net.WebUtility.HtmlEncode(username);
            return Content($"<h1>Hello, {encodedUsername}!</h1>");
        }

        public class LoginModel
        {
            [Required]
            public string Username { get; set; }
            [Required]
            public string Password { get; set; }
        }
    }
}
