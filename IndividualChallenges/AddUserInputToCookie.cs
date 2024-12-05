public void AddUserInputToCookie(string userInput, string userIp, string userAgent)
{
    try
    {
        // Step 1: Whitelist-based Input Validation
        string sanitizedInput = ValidateAndSanitizeInput(userInput);

        // Step 2: Encrypt the sanitized input with a key from a key management system (KMS)
        string encryptedData = EncryptDataWithKMS(sanitizedInput);

        // Step 3: Add Tamper-Proof Cryptographic Signature
        string signedData = AddTamperProofSignature(encryptedData);

        // Step 4: Store Sensitive Data Securely on the Server
        string sessionToken = StoreSessionDataOnServer(signedData, userIp, userAgent);

        // Step 5: Create a Secure Cookie with the Session Token
        HttpCookie cookie = new HttpCookie("SecureSessionID", sessionToken)
        {
            HttpOnly = true,                // Prevent JavaScript access
            Secure = true,                  // Allow only HTTPS connections
            SameSite = SameSiteMode.Strict, // Prevent CSRF
            Expires = DateTime.UtcNow.AddMinutes(15) // Short-lived cookie for extra security
        };

        // Step 6: Add the cookie to the response
        Response.Cookies.Add(cookie);

        // Optional: Log the action without sensitive data
        Console.WriteLine("Extremely secure cookie added successfully.");
    }
    catch (Exception ex)
    {
        // Handle errors gracefully and securely
        Console.WriteLine("Error adding secure cookie: " + ex.Message);
    }
}

// Validate input using a strict whitelist approach
private string ValidateAndSanitizeInput(string input)
{
    if (string.IsNullOrEmpty(input) || input.Length > 50) // Length validation
    {
        throw new ArgumentException("Invalid input");
    }

    // Allow only alphanumeric and a few safe characters
    if (!Regex.IsMatch(input, @"^[a-zA-Z0-9-_]+$"))
    {
        throw new ArgumentException("Input contains invalid characters");
    }

    return HttpUtility.HtmlEncode(input); // Sanitize to prevent XSS
}

// Encrypt the data using a key management system (KMS)
private string EncryptDataWithKMS(string data)
{
    var protector = DataProtectionProvider.Create("AppName").CreateProtector("ExtremeCookies");
    return protector.Protect(data); // This would typically interface with a key vault
}

// Add a tamper-proof cryptographic signature to the data
private string AddTamperProofSignature(string encryptedData)
{
    using (var hmac = new HMACSHA256(GetSigningKey()))
    {
        byte[] signatureBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(encryptedData));
        string signature = Convert.ToBase64String(signatureBytes);
        return $"{encryptedData}.{signature}"; // Concatenate encrypted data with the signature
    }
}

// Store sensitive data on the server securely
private string StoreSessionDataOnServer(string signedData, string userIp, string userAgent)
{
    string sessionId = Guid.NewGuid().ToString(); // Generate a unique session token

    // Store session data securely in a database or in-memory cache (e.g., Redis)
    SecureSessionStore.Add(sessionId, new
    {
        Data = signedData,
        IP = userIp,
        UserAgent = userAgent,
        CreatedAt = DateTime.UtcNow
    });

    return sessionId;
}

// Retrieve the cryptographic signing key securely
private byte[] GetSigningKey()
{
    // Ideally fetch this key securely from a key vault or HSM
    return Encoding.UTF8.GetBytes("YourSecureSigningKeyHere");
}
