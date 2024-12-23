using System.ComponentModel.DataAnnotations;

public class Duyuru
{
    [Key]
    public int Id { get; set; }



    public string? Konu { get; set; }
    public string? Icerik { get; set; }
    public DateTime DuyuruTarih { get; set; }



    public int? AdminId { get; set; }
    public Admin? Admins { get; set; }


}
