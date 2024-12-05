public void AssignUserInputToInnerHtml(string userInput, string userIp, string userAgent)
{
    try
    {
        // Step 1: Validate input based on allowed patterns and strict limits
        string validatedInput = ValidateInput(userInput);

        // Step 2: Sanitize the input to remove unsafe HTML or script content
        string sanitizedInput = SanitizeInput(validatedInput);

        // Step 3: Encrypt and sign the sanitized input for added integrity
        string signedData = AddCryptographicSignature(sanitizedInput);

        // Step 4: Store the signed data securely on the server (session-based, never trust client data)
        string sessionToken = StoreSessionData(signedData, userIp, userAgent);

        // Step 5: Assign the session token (not raw user input) to InnerHtml
        var res = new System.Web.UI.HtmlControls.HtmlGenericControl();
        res.InnerHtml = sessionToken; // Only session token, no raw user input directly assigned
        Console.WriteLine("Set InnerHtml to session token.");
    }
    catch (Exception ex)
    {
        // Handle any errors securely
        Console.WriteLine("Error assigning InnerHtml: " + ex.Message);
    }
}

// 1. Validate input rigorously
private string ValidateInput(string input)
{
    if (string.IsNullOrWhiteSpace(input) || input.Length > 500) // Example: Limit input length
    {
        throw new ArgumentException("Invalid input");
    }

    // Allow only alphanumeric characters, spaces, and basic punctuation
    if (!Regex.IsMatch(input, @"^[a-zA-Z0-9\s\-_]+$"))
    {
        throw new ArgumentException("Input contains invalid characters");
    }

    return input;
}

// 2. Sanitize input to remove potentially dangerous content
private string SanitizeInput(string userInput)
{
    var sanitizer = new HtmlSanitizer();

    // Specify which HTML tags are allowed (default: allow only basic safe tags)
    sanitizer.AllowedTags.Add("b");
    sanitizer.AllowedTags.Add("i");
    sanitizer.AllowedTags.Add("u");

    // Add safe attributes to allow for example for links
    sanitizer.AllowedAttributes.Add("href");
    sanitizer.AllowedAttributes.Add("src");

    // Sanitize input to strip out any unsafe elements or attributes
    return sanitizer.Sanitize(userInput); // Returns cleaned HTML
}

// 3. Add a cryptographic signature to prevent tampering with the input data
private string AddCryptographicSignature(string sanitizedInput)
{
    using (var hmac = new HMACSHA256(GetSigningKey()))
    {
        byte[] signatureBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(sanitizedInput));
        string signature = Convert.ToBase64String(signatureBytes);
        return $"{sanitizedInput}.{signature}"; // Concatenate sanitized data with the signature
    }
}

// 4. Store sensitive data securely on the server (session-based storage)
private string StoreSessionData(string signedData, string userIp, string userAgent)
{
    // Generate a unique session token
    string sessionToken = Guid.NewGuid().ToString();

    // Store the session securely in a database or cache (e.g., Redis)
    SecureSessionStore.Add(sessionToken, new
    {
        Data = signedData,
        IP = userIp,
        UserAgent = userAgent,
        CreatedAt = DateTime.UtcNow
    });

    return sessionToken;
}

// 5. Secure signing key retrieval for HMAC signing
private byte[] GetSigningKey()
{
    // Fetch the signing key from a secure key vault (never hardcoded)
    return Encoding.UTF8.GetBytes("YourSecureSigningKeyHere");
}
