public void ThrowGenericException(Exception ex)
{
    try
    {
        DoSomethingRisky();
    }
    catch (Exception innerEx)
    {
        // Log the original exception details for debugging purposes
        LogException(innerEx);

        // Throw a custom exception without exposing sensitive details
        throw new CustomException("An error occurred while processing your request.");
    }
}

private void DoSomethingRisky()
{
    throw new ArgumentNullException("Parameter cannot be null.");
}

private void LogException(Exception ex)
{
    // Implement your logging mechanism here
    // For example, log to a file, database, or monitoring system
    Console.WriteLine($"Exception: {ex.Message}, StackTrace: {ex.StackTrace}");
}

// Custom exception class
public class CustomException : Exception
{
    public CustomException(string message) : base(message) { }
}
