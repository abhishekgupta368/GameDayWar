using Microsoft.AspNetCore.Mvc;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Antiforgery;

namespace SecureWebAPI
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IAntiforgery _antiforgery;

        public UserController(IAntiforgery antiforgery)
        {
            _antiforgery = antiforgery;
        }

        // 1. Fixing XSS Vulnerability by encoding user input
        [HttpGet("greet")]
        public IActionResult GreetUser(string username)
        {
            string encodedUsername = System.Net.WebUtility.HtmlEncode(username);
            return Content($"<h1>Welcome, {encodedUsername}</h1>");
        }

        // 2. Fixing Insecure File Handling by storing data in a secure directory
        [HttpPost("storeData")]
        public IActionResult StoreData([FromBody] string data)
        {
            string securePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "SecureData", "user_info.txt");
            Directory.CreateDirectory(Path.GetDirectoryName(securePath));
            File.WriteAllText(securePath, data);
            return Ok("Data stored securely");
        }

        // 3. Fixing Weak Cryptography by using a stronger hashing algorithm (SHA256)
        [HttpPost("storePassword")]
        public IActionResult StorePassword([FromBody] string password)
        {
            string hashedPassword = HashPasswordWithSHA256(password);
            string securePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "SecureData", "passwords.txt");
            Directory.CreateDirectory(Path.GetDirectoryName(securePath));
            File.WriteAllText(securePath, hashedPassword);
            return Ok("Password stored securely");
        }

        private string HashPasswordWithSHA256(string password)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                StringBuilder builder = new StringBuilder();
                foreach (byte b in bytes)
                {
                    builder.Append(b.ToString("x2"));
                }
                return builder.ToString();
            }
        }

        // 4. Fixing CSRF Vulnerability by validating anti-forgery tokens
        [HttpPost("updateEmail")]
        [ValidateAntiForgeryToken]
        public IActionResult UpdateEmail([FromBody] string email)
        {
            string securePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "SecureData", "user_email.txt");
            Directory.CreateDirectory(Path.GetDirectoryName(securePath));
            File.WriteAllText(securePath, email);
            return Ok("Email updated securely");
        }

        // 5. Avoid logging sensitive data
        [HttpPost("logUserAction")]
        public IActionResult LogUserAction([FromBody] string action)
        {
            // Avoid logging sensitive actions
            return Ok("Action received but not logged for security reasons");
        }
    }
}
