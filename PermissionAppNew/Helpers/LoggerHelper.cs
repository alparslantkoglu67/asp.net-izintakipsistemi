public static class LoggerHelper
{
    public static async Task LogAsync(DataContext context, int? userId, string action, string description, int? internId, int? adminId)
    {
        var log = new Log
        {
            InternId = internId,
            AdminId = adminId,
            UserId = userId,
            Action = action,
            Description = description,
            Timestamp = DateTime.UtcNow
        };
        context.Logs.Add(log);
        await context.SaveChangesAsync();
    }
}