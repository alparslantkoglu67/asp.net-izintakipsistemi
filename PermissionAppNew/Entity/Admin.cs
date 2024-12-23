using System.ComponentModel.DataAnnotations;

public class Admin
{
    [Key]
    public int Id { get; set; }



    public string? Name { get; set; }
    public string? SurName { get; set; }
    public string? NickName { get; set; }


    public string? AdSoyad
    {
        get
        {
            return this.Name + " " + this.SurName;
        }
    }




    public string? Email { get; set; }
    public string? Password { get; set; }
    public ICollection<Log>? Logs { get; set; }

    public virtual ICollection<LeaveDay>? LeaveDays { get; set; }
    public virtual ICollection<Duyuru>? Duyurus { get; set; }


}
