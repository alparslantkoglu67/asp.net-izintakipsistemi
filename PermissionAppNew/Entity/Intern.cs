using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

public class Intern
{
    [Key]
    public int Id { get; set; }

    [Required]
    [StringLength(100)]
    public string Name { get; set; } = null!;


    [Required]
    [StringLength(100)]
    public string SurName { get; set; } = null!;


    [Required]
    [StringLength(100)]
    public string NickName { get; set; } = null!;


    [Required]
    [PasswordPropertyText]
    public string Password { get; set; } = null!;


    public string? AdSoyad
    {
        get
        {
            return this.Name + " " + this.SurName;
        }
    }
    [Required]
    public int Age { get; set; }

    [Required]
    [EmailAddress]
    public string Email { get; set; } = null!;

    [Required]
    [StringLength(100)]
    public string Okul { get; set; } = null!;


    [Required]
    [StringLength(100)]
    public string Position { get; set; } = null!;


    [Required]
    [Phone]
    public string Phone { get; set; } = null!;


    [Required]
    public DateTime stajBaslama { get; set; }


    [Required]
    public DateTime stajBitis { get; set; }
    public ICollection<Log>? Logs { get; set; }


    public virtual ICollection<LeaveDay>? LeaveDays { get; set; }


}
