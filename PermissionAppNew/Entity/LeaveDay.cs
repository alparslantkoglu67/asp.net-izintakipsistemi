using System.ComponentModel.DataAnnotations;

public class LeaveDay
{
    [Key]
    public int Id { get; set; }




    [Required(ErrorMessage = "Başlangıç tarihi gereklidir.")]
    [DataType(DataType.Date)]
    public DateTime StartDate { get; set; }

    [Required(ErrorMessage = "Bitiş tarihi gereklidir.")]
    [DataType(DataType.Date)]
    public DateTime EndDate { get; set; }

    [Required(ErrorMessage = "İzin türü gereklidir.")]
    public string? LeaveType { get; set; }
    public DateTime IzinAlimTarihi { get; set; } = DateTime.Now;
    public string IzinOnayDurumu { get; set; } = "Beklemede";





    public int? InternId { get; set; }
    public Intern? Interns { get; set; }
    public int? UserId { get; set; }
    public User? Users { get; set; }

    public int? AdminId { get; set; }
    public Admin? Admins { get; set; }

    public ICollection<Log>? Logs { get; set; }

}
