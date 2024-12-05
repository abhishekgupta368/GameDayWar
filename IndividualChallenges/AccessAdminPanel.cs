public class AdminAccessService
{
    public void AccessAdminPanel(string username, string password, string otp, string requestIPAddress)
    {
        if (!AuthenticateUser(username, password))
        {
            Console.WriteLine("Access Denied: Invalid Credentials.");
            LogAccessAttempt(username, requestIPAddress, success: false);
            return;
        }

        if (IsAccountLocked(username))
        {
            Console.WriteLine("Access Denied: Account Locked.");
            return;
        }

        if (!VerifyMFA(username, otp))
        {
            Console.WriteLine("Access Denied: MFA Failed.");
            return;
        }

        if (!IsTrustedIP(requestIPAddress))
        {
            Console.WriteLine("Access Denied: Untrusted IP Address.");
            return;
        }

        if (!HasPermission(username, "AdminPanel"))
        {
            Console.WriteLine("Access Denied: Insufficient Permissions.");
            return;
        }

        Console.WriteLine("Access Granted: Welcome to the Admin Panel!");
        LogAccessAttempt(username, requestIPAddress, success: true);
    }

    private bool AuthenticateUser(string username, string password)
    {
        // Securely authenticate using hashed passwords
        return UserDatabase.VerifyCredentials(username, password);
    }

    private bool VerifyMFA(string username, string otp)
    {
        // Verify OTP
        return MFAService.VerifyOTP(username, otp);
    }

    private bool IsTrustedIP(string ipAddress)
    {
        // Check against a list of trusted IPs
        return TrustedIPList.Contains(ipAddress);
    }

    private bool HasPermission(string username, string action)
    {
        // Check role and permissions
        return UserPermissions.HasAccess(username, action);
    }

    private void LogAccessAttempt(string username, string ipAddress, bool success)
    {
        // Log attempt for auditing
        AuditLogger.Log(username, ipAddress, success);
    }
}
