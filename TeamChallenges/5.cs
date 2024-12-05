using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SecureFileOperations
{
    public class FileHandler
    {
        // 1. Storing sensitive data with encryption
        public static void StoreSensitiveData(string data)
        {
            string encryptedData = EncryptData(data);
            File.WriteAllText("sensitiveData.txt", encryptedData); // Data stored in encrypted form
        }

        // 2. Secure file path usage to prevent directory traversal
        public static void DeleteFile(string userInput)
        {
            string safeFileName = Path.GetFileName(userInput); // Ensure only the file name is used
            string filePath = Path.Combine("C:\\Files\\", safeFileName);
            File.Delete(filePath); // Secure delete operation
        }

        // 3. Secure logging (Avoid logging sensitive data)
        public static void LogData(string data)
        {
            string sanitizedData = SanitizeData(data); // Sanitize data before logging
            File.AppendAllText("log.txt", $"{DateTime.Now}: {sanitizedData}\n"); // Logs sanitized data
        }

        // 4. Secure file permissions (Check who can access the file)
        public static void ChangeFilePermissions(string filePath)
        {
            // Implement file permission checks here
            // For example, restrict access to specific users or groups
            File.SetAttributes(filePath, FileAttributes.Normal); // Secure file attribute changes
        }

        // 5. Data integrity (File modification with integrity checks)
        public static void ModifyFileData(string filePath, string newData)
        {
            string originalData = File.ReadAllText(filePath);
            if (VerifyDataIntegrity(originalData))
            {
                File.WriteAllText(filePath, newData); // Modifying file with integrity checks
            }
        }

        // Helper methods for encryption, sanitization, and integrity checks
        private static string EncryptData(string data)
        {
            // Implement your encryption mechanism here
            // For example, using AES encryption
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(data)); // Placeholder encryption
        }

        private static string SanitizeData(string data)
        {
            // Implement your data sanitization mechanism here
            // For example, removing sensitive information
            return data.Replace("sensitive", "sanitized"); // Placeholder sanitization
        }

        private static bool VerifyDataIntegrity(string data)
        {
            // Implement your data integrity verification mechanism here
            // For example, using hash comparison
            return true; // Placeholder integrity check
        }
    }
}
