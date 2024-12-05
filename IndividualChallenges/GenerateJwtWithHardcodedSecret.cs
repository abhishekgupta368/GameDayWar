public void GenerateJwtWithHardcodedSecret(string username)
{
    const string jwtSecret = ENV.secret; // Reading from env
    Console.WriteLine("Generating JWT with hardcoded secret.");

    // Simulate JWT creation
    var payload = $"{{ \"username\": \"{username}\" }}";
    var signature = Convert.ToBase64String(Encoding.UTF8.GetBytes(jwtSecret));
    var jwt = $"{Convert.ToBase64String(Encoding.UTF8.GetBytes(payload))}.{signature}";

    Console.WriteLine("Generated JWT: " + jwt);
}
