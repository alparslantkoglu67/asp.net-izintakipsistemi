public class Log
{
    public int Id { get; set; }
    public string Action { get; set; } = string.Empty;
    public string? Description { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public int? InternId { get; set; }
    public Intern? Interns { get; set; }
    public int? UserId { get; set; }
    public User? Users { get; set; }
    public int? LeaveDayId { get; set; }
    public LeaveDay? LeaveDays { get; set; }
    public int? AdminId { get; set; }
    public Admin? Admins { get; set; }
}