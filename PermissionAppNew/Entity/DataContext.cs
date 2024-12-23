using Microsoft.EntityFrameworkCore;

public class DataContext : DbContext
{
    public DataContext(DbContextOptions<DataContext> options) : base(options) { }

    public DbSet<User> Users { get; set; }
    public DbSet<Intern> Interns { get; set; }
    public DbSet<LeaveDay> LeaveDays { get; set; }
    public DbSet<Admin> Admins { get; set; }
    public DbSet<Duyuru> Duyurus { get; set; }
    public DbSet<Log> Logs { get; set; }
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Log ile Intern arasındaki ilişkiyi tanımlıyoruz
        modelBuilder.Entity<Log>()
            .HasOne(l => l.Interns) // Log'un Intern ile ilişkisi
            .WithMany(i => i.Logs) // Intern'in birden fazla Log'u var
            .HasForeignKey(l => l.InternId) // Foreign Key (InternId)
            .OnDelete(DeleteBehavior.Restrict); // Intern silindiğinde log silinmesin

        // Log ile User arasındaki ilişkiyi tanımlıyoruz
        modelBuilder.Entity<Log>()
            .HasOne(l => l.Users) // Log'un User ile ilişkisi
            .WithMany(u => u.Logs) // User'ın birden fazla Log'u var
            .HasForeignKey(l => l.UserId) // Foreign Key (UserId)
            .OnDelete(DeleteBehavior.Restrict); // User silindiğinde log silinmesin

        // Log ile Admin arasındaki ilişkiyi tanımlıyoruz
        modelBuilder.Entity<Log>()
            .HasOne(l => l.Admins) // Log'un Admin ile ilişkisi
            .WithMany(a => a.Logs) // Admin'in birden fazla Log'u var
            .HasForeignKey(l => l.AdminId) // Foreign Key (AdminId)
            .OnDelete(DeleteBehavior.Restrict); // Admin silindiğinde log silinmesin

        // Log ile LeaveDay arasındaki ilişkiyi tanımlıyoruz
        modelBuilder.Entity<Log>()
            .HasOne(l => l.LeaveDays) // Log'un LeaveDay ile ilişkisi
            .WithMany(ld => ld.Logs) // LeaveDay'in birden fazla Log'u var
            .HasForeignKey(l => l.LeaveDayId) // Foreign Key (LeaveDayId)
            .OnDelete(DeleteBehavior.Restrict); // LeaveDay silindiğinde log silinmesin

        base.OnModelCreating(modelBuilder);
    }

}
