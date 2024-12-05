using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace SecureCryptographyLibrary
{
    public class SecureCryptography
    {
        // 1. SHA-256 Hashing (Strong Cryptography)
        public static string HashPassword(string password)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }
        }

        // 2. Storing sensitive data with encryption
        public static void StoreData(string data)
        {
            string encryptedData = EncryptData(data);
            File.WriteAllText("sensitiveData.txt", encryptedData); // Storing data securely
        }

        // 3. Strong Token Generation (Secure Randomness)
        public static string GenerateToken()
        {
            byte[] tokenBytes = new byte; // Increased token size for better security
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(tokenBytes);
            }
            return Convert.ToBase64String(tokenBytes); // Strong token generation
        }

        // 4. Using strong ciphers (AES)
        public static string EncryptData(string data)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = GenerateRandomKey();
                aes.IV = GenerateRandomIV();
                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    byte[] dataBytes = Encoding.UTF8.GetBytes(data);
                    return Convert.ToBase64String(encryptor.TransformFinalBlock(dataBytes, 0, dataBytes.Length));
                }
            }
        }

        // 5. Storing session tokens securely
        public static void StoreSessionToken(string token)
        {
            string encryptedToken = EncryptData(token);
            File.AppendAllText("sessionTokens.txt", encryptedToken); // Secure storage of session tokens
        }

        // Helper methods for generating random keys and IVs
        private static byte[] GenerateRandomKey()
        {
            byte[] key = new byte; // 256-bit key for AES
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }
            return key;
        }

        private static byte[] GenerateRandomIV()
        {
            byte[] iv = new byte; // 128-bit IV for AES
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv);
            }
            return iv;
        }
    }
}
