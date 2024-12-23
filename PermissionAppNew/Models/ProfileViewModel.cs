public class ProfileViewModel
{
    public User? Users { get; set; }
    public Intern? Interns { get; set; }
    public Admin? Admins { get; set; }

    public List<LeaveDay>? LeaveDays { get; set; }
}