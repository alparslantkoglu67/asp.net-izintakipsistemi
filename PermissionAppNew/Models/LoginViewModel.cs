using System.ComponentModel.DataAnnotations;

namespace PermissionAppNew.Models
{
    public class LoginViewModel
    {
        [Required(ErrorMessage = "Kullanıcı adı alanı boş bırakılamaz.")]
        [Display(Name = "Kullanıcı Adı")]
        public string UserName { get; set; } = null!;

        [Required(ErrorMessage = "Parola alanı boş bırakılamaz.")]
        [Display(Name = "Parola")]
        [StringLength(10, ErrorMessage = "Parola en fazla 10 ve en az 6 karakter olmalıdır!", MinimumLength = 6)]
        [DataType(DataType.Password)]
        public string UserPassword { get; set; } = null!;
    }
}
