using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using PermissionAppNew.Data.Abstract;
using PermissionAppNew.Models;
using System.Diagnostics.Eventing.Reader;
using System.Security.Claims;

public class UserController : Controller
{
    private readonly DataContext _context;
    private readonly IUserRepository _userRepository;
    private readonly IInternRepository _internRepository;
    private readonly IAdminRepository _adminRepository;



    public UserController(DataContext context, IUserRepository userRepository, IInternRepository internRepository, IAdminRepository adminRepository)
    {
        _context = context;
        _userRepository = userRepository;
        _internRepository = internRepository;
        _adminRepository = adminRepository;
    }
    public IActionResult Login()//OK
    {
        if (User.Identity!.IsAuthenticated)
        {
            return RedirectToAction("Duyuru", "User");

        }
        return View();
    }
    [HttpPost]
    public async Task<IActionResult> Login(LoginViewModel model)//OK
    {
        if (ModelState.IsValid)
        {
            var isUser = _userRepository.Users.FirstOrDefault(x => x.NickName == model.UserName && x.Password == model.UserPassword);
            var isIntern = _internRepository.Interns.FirstOrDefault(x => x.NickName == model.UserName && x.Password == model.UserPassword);
            var isAdmin = _adminRepository.Admins.FirstOrDefault(x => x.NickName == model.UserName &&
            x.Password == model.UserPassword);
            if (isAdmin != null)
            {
                var adminClaims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, isAdmin.Id.ToString()),
                new Claim(ClaimTypes.Name, isAdmin.NickName!),
                new Claim(ClaimTypes.GivenName, isAdmin.AdSoyad ?? ""),
                new Claim(ClaimTypes.Role, "Admin")
            };
                var claimsIdentity = new ClaimsIdentity(adminClaims, CookieAuthenticationDefaults.AuthenticationScheme);
                var authProperties = new AuthenticationProperties
                {
                    IsPersistent = true
                };

                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity),
                    authProperties);
                try
                {
                    try
                    {
                        await LoggerHelper.LogAsync(
                            _context,
                            userId: null,
                            action: "Giriş Yap(Adminler)",
                            description: $"{isAdmin.Id} ID'li, {isAdmin.NickName} kullanıcı adlı, {isAdmin.AdSoyad} isimli admin giriş yapmıştır.",
                            internId: null,
                            adminId: isAdmin.Id
                        );
                    }
                    catch (Exception logEx)
                    {
                        ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                        return View(model);
                    }


                }

                catch (Exception ex)
                {
                    ModelState.AddModelError("", $"Veritabanına kaydetme işlemi sırasında bir hata oluştu: {ex.Message}");
                }

                return RedirectToAction("Duyuru", "User");
            }
            else if (isUser != null)
            {
                var userClaims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, isUser.Id.ToString()),
                new Claim(ClaimTypes.Name, isUser.NickName),
                new Claim(ClaimTypes.GivenName, isUser.AdSoyad ?? ""),
                new Claim(ClaimTypes.Role, "User")
            };
                var claimsIdentity = new ClaimsIdentity(userClaims, CookieAuthenticationDefaults.AuthenticationScheme);
                var authProperties = new AuthenticationProperties
                {
                    IsPersistent = true
                };

                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity),
                    authProperties);

                try
                {
                    try
                    {
                        await LoggerHelper.LogAsync(
                            _context,
                            userId: isUser.Id,
                            action: "Giriş Yap(Çalışanlar)",
                            description: $"{isUser.Id} ID'li, {isUser.NickName} kullanıcı adlı, {isUser.AdSoyad} isimli çalışan giriş yapmıştır.",
                            internId: null,
                            adminId: null
                        );
                    }
                    catch (Exception logEx)
                    {
                        ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                        return View(model);
                    }

                    return RedirectToAction("Permission");
                }
                catch (Exception ex)
                {
                    ModelState.AddModelError("", $"Veritabanına kaydetme işlemi sırasında bir hata oluştu: {ex.Message}");
                }



                return RedirectToAction("Duyuru", "User");
            }

            else if (isIntern != null)
            {
                var internClaims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, isIntern.Id.ToString()),
                new Claim(ClaimTypes.Name, isIntern.NickName),
                new Claim(ClaimTypes.GivenName, isIntern.AdSoyad ?? ""),
                new Claim(ClaimTypes.Role, "Intern")
            };

                var claimsIdentity = new ClaimsIdentity(internClaims, CookieAuthenticationDefaults.AuthenticationScheme);
                var authProperties = new AuthenticationProperties
                {
                    IsPersistent = true
                };

                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity),
                    authProperties);
                try
                {
                    try
                    {
                        await LoggerHelper.LogAsync(
                            _context,
                            userId: null,
                            action: "Giriş Yap(Stajyerler)",
                            description: $"{isIntern.Id} ID'li, {isIntern.NickName} kullanıcı adlı, {isIntern.AdSoyad} isimli stajyer giriş yapmıştır.",
                            internId: isIntern.Id,
                            adminId: null
                        );
                    }
                    catch (Exception logEx)
                    {
                        ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                        return View(model);
                    }


                }

                catch (Exception ex)
                {
                    ModelState.AddModelError("", $"Veritabanına kaydetme işlemi sırasında bir hata oluştu: {ex.Message}");
                }

                return RedirectToAction("Duyuru", "User");
            }

        }

        return RedirectToAction(nameof(Login));
    }

    public IActionResult CreateUser()//OK
    {
        return View();

    }
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CreateUser(User model)//OK
    {

        if (ModelState.IsValid)
        {
            try
            {
                var NickName = User.FindFirst(ClaimTypes.Name)?.Value;

                int? oturumcuId = null;
                var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                if (userIdClaim != null)
                {
                    var role = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;

                    oturumcuId = int.Parse(userIdClaim);
                    _context.Users.Add(model);
                    await _context.SaveChangesAsync();

                    // Log kaydı
                    try
                    {
                        await LoggerHelper.LogAsync(
                            _context,
                            userId: null,
                            action: "Çalışan Oluştur(Adminler)",
                            description: $"{model.NickName}  adlı çalışan {NickName} tarafından oluşturulmuştur. (ID'si: {model.Id} KullanıcıAdı:{model.NickName} AdıSoyadı: {model.AdSoyad} Yaşı: {model.Age} Bölümü: {model.Position} Telefon: {model.Phone} Mail: {model.Email} Şifre: {model.Password} )",
                            internId: null,
                            adminId: oturumcuId
                        );
                    }
                    catch (Exception logEx)
                    {
                        ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                        return View(model);
                    }

                    // Yeni kullanıcı ekleme


                    return RedirectToAction(nameof(Login));
                }
                else
                {
                    // Yeni kullanıcı ekleme
                    _context.Users.Add(model);
                    await _context.SaveChangesAsync();

                    // Log kaydı
                    try
                    {
                        await LoggerHelper.LogAsync(
                            _context,
                            userId: model.Id,
                            action: "Çalışan Oluştur(noname)",
                            description: $"{model.NickName}  adlı çalışan kendisi tarafından oluşturulmuştur. (ID'si: {model.Id} KullanıcıAdı: {model.NickName} AdıSoyadı: {model.AdSoyad} Yaşı: {model.Age} Bölümü: {model.Position} Telefon: {model.Phone} Mail: {model.Email} Şifre:  {model.Password} )",
                            internId: null,
                            adminId: null
                        );
                    }
                    catch (Exception logEx)
                    {
                        ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                        return View(model);
                    }

                    return RedirectToAction(nameof(Login));
                }
            }
            catch (DbUpdateException ex) when (ex.InnerException?.Message.Contains("database is locked") == true)
            {
                ModelState.AddModelError("", "Veritabanı şu anda meşgul. Lütfen tekrar deneyin.");
            }
            catch (Exception ex)
            {
                ModelState.AddModelError("", $"Bir hata oluştu: {ex.Message}");
                Console.WriteLine($"Log işlemi sırasında hata: {ex.Message}");
            }
        }

        return View(model);
    }

    public IActionResult CreateIntern()//OK
    {

        return View();


    }
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CreateIntern(Intern model)//OK
    {
        if (ModelState.IsValid)
        {
            try
            {
                var NickName = User.FindFirst(ClaimTypes.Name)?.Value;
                int? oturumcuId = null;
                var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                if (userIdClaim != null)
                {


                    var role = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;
                    oturumcuId = int.Parse(userIdClaim);
                    _context.Interns.Add(model);
                    await _context.SaveChangesAsync();

                    // Log kaydı
                    try
                    {
                        await LoggerHelper.LogAsync(
                            _context,
                            userId: null,
                            action: "Stajyer Oluştur(Adminler)",
                            description: $"{model.NickName}  adlı stajyer {NickName} tarafından oluşturulmuştur. (ID'si: {model.Id} KullanıcıAdı: {model.NickName} AdıSoyadı:{model.AdSoyad} Yaşı: {model.Age} Bölümü: {model.Position} Telefon: {model.Phone} Mail: {model.Email} Şifre: {model.Password} Okul: {model.Okul} StajBaşlama: {model.stajBaslama} Staj Bitiş: {model.stajBitis})",
                            internId: null,
                            adminId: oturumcuId
                        );
                    }
                    catch (Exception logEx)
                    {
                        ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                        return View(model);
                    }

                    // Yeni kullanıcı ekleme


                    return RedirectToAction(nameof(Login));
                }
                else
                {
                    // Yeni kullanıcı ekleme
                    _context.Interns.Add(model);
                    await _context.SaveChangesAsync();

                    // Log kaydı
                    try
                    {
                        await LoggerHelper.LogAsync(
                            _context,
                            userId: null,
                            action: "Stajyer Oluştur(noname)",
                            description: $"{model.NickName}  adlı stajyer kendisi tarafından oluşturulmuştur. (ID'si: {model.Id} KullanıcıAdı: {model.NickName} AdıSoyadı: {model.AdSoyad} Yaşı: {model.Age} Bölümü: {model.Position} Telefon: {model.Phone} Mail: {model.Email} Şifre: {model.Password} Okul: {model.Okul} StajBaşlama: {model.stajBaslama} Staj Bitiş: {model.stajBitis})",
                            internId: model.Id,
                            adminId: null
                        );
                    }
                    catch (Exception logEx)
                    {
                        ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                        return View(model);
                    }

                    return RedirectToAction(nameof(Login));
                }
            }
            catch (DbUpdateException ex) when (ex.InnerException?.Message.Contains("database is locked") == true)
            {
                ModelState.AddModelError("", "Veritabanı şu anda meşgul. Lütfen tekrar deneyin.");
            }
            catch (Exception ex)
            {
                ModelState.AddModelError("", $"Bir hata oluştu: {ex.Message}");
                Console.WriteLine($"Log işlemi sırasında hata: {ex.Message}");
            }
        }

        return View(model);
    }

    public async Task<IActionResult> UserList()//OK
    {
        var role = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;
        if (User.Identity!.IsAuthenticated == false)
        {
            if (role != "Admin")
            {
                return RedirectToAction("Login", "User");
            }

        }
        return View(await _context.Users.ToListAsync());
    }
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteUserList(int id)//OK

    {
        var user = await _context.Users
            .Include(u => u.LeaveDays)
            .FirstOrDefaultAsync(x => x.Id == id);

        if (user == null)
        {
            return NotFound();
        }


        if (user.LeaveDays != null && user.LeaveDays.Any())
        {
            _context.LeaveDays.RemoveRange(user.LeaveDays);
        }


        if (ModelState.IsValid)
        {
            try
            {
                var NickName = User.FindFirst(ClaimTypes.Name)?.Value;
                int? oturumcuId = null;
                var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                if (userIdClaim != null)
                {
                    var role = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;
                    oturumcuId = int.Parse(userIdClaim);
                    _context.Users.Remove(user);
                    await _context.SaveChangesAsync();

                    // Log kaydı
                    try
                    {
                        await LoggerHelper.LogAsync(
                            _context,
                            userId: null,
                            action: "Çalışan Sil",
                            description: $"{user.NickName}  adlı çalışan {NickName} tarafından silinmiştir. (ID'si: {user.Id} KullanıcıAdı:{user.NickName} AdıSoyadı:{user.AdSoyad} Yaşı:{user.Age} Bölümü:{user.Position} Telefon:{user.Phone} Mail:{user.Email} Şifre:{user.Password})",
                            internId: null,
                            adminId: oturumcuId
                        );
                    }
                    catch (Exception logEx)
                    {
                        ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                        return View(user);
                    }

                    // Yeni kullanıcı ekleme


                    return RedirectToAction(nameof(Login));
                }

            }
            catch (DbUpdateException ex) when (ex.InnerException?.Message.Contains("database is locked") == true)
            {
                ModelState.AddModelError("", "Veritabanı şu anda meşgul. Lütfen tekrar deneyin.");
            }
            catch (Exception ex)
            {
                ModelState.AddModelError("", $"Bir hata oluştu: {ex.Message}");
                Console.WriteLine($"Log işlemi sırasında hata: {ex.Message}");
            }
        }

        return View(user);

    }


    [HttpGet]
    public async Task<IActionResult> UpdateUserList(int? id)//OK
    {
        if (id == null)
        {
            return NotFound();
        }
        var user = await _context.Users
        .Include(u => u.LeaveDays)
        .FirstOrDefaultAsync(x => x.Id == id);
        if (user == null)
        {
            return NotFound();
        }
        return View(user);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> UpdateUserList(int id, User model)//OK
    {
        if (id != model.Id)
        {
            return NotFound();
        }

        if (ModelState.IsValid)
        {
            int? oturumcuId = null;
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var NickName = User.FindFirst(ClaimTypes.Name)?.Value;


            if (userIdClaim != null)
            {

                var role = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;
                oturumcuId = int.Parse(userIdClaim);
                try
                {


                    _context.Update(model);
                    await _context.SaveChangesAsync();
                    try
                    {
                        await LoggerHelper.LogAsync(
                            _context,
                            userId: null,
                            action: "Çalışan Güncelle",
                            description: $"{model.NickName}  adlı çalışan {NickName} tarafından güncellenmiştir. (ID'si: {model.Id} KullanıcıAdı:{model.NickName} AdıSoyadı:{model.AdSoyad} Yaşı:{model.Age} Bölümü:{model.Position} Telefon:{model.Phone} Mail:{model.Email} Şifre:{model.Password})",
                            internId: null,
                            adminId: oturumcuId
                        );
                    }
                    catch (Exception logEx)
                    {
                        ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                        return View(model);
                    }

                    return RedirectToAction("UserList", "User");

                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!_context.Users.Any(o => o.Id == model.Id))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
            }
        }

        return View(model);
    }

    public async Task<IActionResult> InternList()//OK
    {
        var role = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;
        if (User.Identity!.IsAuthenticated == false)
        {
            if (role != "Admin")
            {
                return RedirectToAction("Login", "User");
            }

        }
        return View(await _context.Interns.ToListAsync());
    }
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteInternList(int id)//OK
    {
        var intern = await _context.Interns
            .Include(u => u.LeaveDays)
            .FirstOrDefaultAsync(x => x.Id == id);

        if (intern == null)
        {
            return NotFound();
        }


        if (intern.LeaveDays != null && intern.LeaveDays.Any())
        {
            _context.LeaveDays.RemoveRange(intern.LeaveDays);
        }


        if (ModelState.IsValid)
        {
            try
            {
                int? oturumcuId = null;
                var NickName = User.FindFirst(ClaimTypes.Name)?.Value;

                var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                if (userIdClaim != null)
                {
                    var role = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;
                    oturumcuId = int.Parse(userIdClaim);
                    _context.Interns.Remove(intern);
                    await _context.SaveChangesAsync();

                    // Log kaydı
                    try
                    {
                        await LoggerHelper.LogAsync(
                            _context,
                            userId: null,
                            action: "Stajyer Sil",
                            description: $"{intern.NickName}  adlı stajyer {NickName} tarafından güncellenmiştir. (ID'si: {intern.Id} KullanıcıAdı:{intern.NickName} AdıSoyadı:{intern.AdSoyad} Yaşı:{intern.Age} Bölümü:{intern.Position} Telefon:{intern.Phone} Mail:{intern.Email} Şifre:{intern.Password} Okul:{intern.Okul} StajBaşlama:{intern.stajBaslama} Staj Bitiş:{intern.stajBitis})",
                            internId: null,
                            adminId: oturumcuId
                        );
                    }
                    catch (Exception logEx)
                    {
                        ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                        return View(intern);
                    }

                    // Yeni kullanıcı ekleme


                    return RedirectToAction(nameof(Login));
                }

            }
            catch (DbUpdateException ex) when (ex.InnerException?.Message.Contains("database is locked") == true)
            {
                ModelState.AddModelError("", "Veritabanı şu anda meşgul. Lütfen tekrar deneyin.");
            }
            catch (Exception ex)
            {
                ModelState.AddModelError("", $"Bir hata oluştu: {ex.Message}");
                Console.WriteLine($"Log işlemi sırasında hata: {ex.Message}");
            }
        }

        return View(intern);

    }
    [HttpGet]
    public async Task<IActionResult> UpdateInternList(int? id)//OK
    {
        if (id == null)
        {
            return NotFound();
        }
        var intern = await _context.Interns
        .Include(u => u.LeaveDays)
        .FirstOrDefaultAsync(x => x.Id == id);
        if (intern == null)
        {
            return NotFound();
        }
        return View(intern);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> UpdateInternList(int id, Intern model)//OK
    {
        if (id != model.Id)
        {
            return NotFound();
        }

        if (ModelState.IsValid)
        {
            int? oturumcuId = null;
            var NickName = User.FindFirst(ClaimTypes.Name)?.Value;
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (userIdClaim != null)
            {
                var role = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;
                oturumcuId = int.Parse(userIdClaim);
                try
                {


                    _context.Update(model);
                    await _context.SaveChangesAsync();
                    try
                    {
                        await LoggerHelper.LogAsync(
                            _context,
                            userId: null,
                            action: "Stajyer Güncelle",
                            description: $"{model.NickName}  adlı stajyer {NickName} tarafından güncellenmiştir. (ID'si: {model.Id} KullanıcıAdı:{model.NickName} AdıSoyadı:{model.AdSoyad} Yaşı:{model.Age} Bölümü:{model.Position} Telefon:{model.Phone} Mail:{model.Email} Şifre:{model.Password} Okul:{model.Okul} StajBaşlama:{model.stajBaslama} Staj Bitiş:{model.stajBitis})",
                            internId: null,
                            adminId: oturumcuId
                        );
                    }
                    catch (Exception logEx)
                    {
                        ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                        return View(model);
                    }

                    return RedirectToAction("InternList", "User");

                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!_context.Interns.Any(o => o.Id == model.Id))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
            }
        }


        return View(model);
    }


    [HttpPost]
    public async Task<IActionResult> Permission(LeaveDay model)//OK
    {
        var oturumId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        var role = User.FindFirst(ClaimTypes.Role)?.Value;
        var NickName = User.FindFirst(ClaimTypes.Name)?.Value;


        if (User.Identity != null && User.Identity.IsAuthenticated)
        {
            if (oturumId == null)
            {
                return RedirectToAction(nameof(Login));
            }
            if (ModelState.IsValid)
            {
                int oturumid = int.Parse(oturumId);
                model.IzinAlimTarihi = DateTime.Now;
                if (role == "User")
                {


                    var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                    if (!string.IsNullOrEmpty(userId))
                    {
                        int userid = int.Parse(userId);
                        model.UserId = int.Parse(userId);
                        try
                        {


                            _context.LeaveDays.Add(model);
                            await _context.SaveChangesAsync();
                            try
                            {
                                await LoggerHelper.LogAsync(
                                    _context,
                                    userId: userid,
                                    action: "İzin Al(Çalışanlar)",
                                    description: $"{userid} ID'li {NickName}  adlı kullanıcı tarafından izin alınmıştır.(İzin alım: {model.StartDate} İzin Bitiş: {model.EndDate} İzin Türü: {model.LeaveType} İzin Onay Durumu: {model.IzinOnayDurumu} İzin Alım Tarihi: {model.IzinAlimTarihi} ) Çalışan ID'si: {oturumid}",
                                    internId: null,
                                    adminId: null
                                );
                            }
                            catch (Exception logEx)
                            {
                                ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                                return View(model);
                            }
                            return RedirectToAction("Permission");
                        }
                        catch (Exception ex)
                        {
                            ModelState.AddModelError("", $"Veritabanına kaydetme işlemi sırasında bir hata oluştu: {ex.Message}");
                        }
                    }
                    else
                    {
                        ModelState.AddModelError("", "Kullanıcı kimliği bulunamadı.");
                    }

                }
                if (role == "Intern")
                {

                    var internId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                    if (!string.IsNullOrEmpty(internId))
                    {
                        int internid = int.Parse(internId);
                        model.InternId = int.Parse(internId);
                        try
                        {
                            _context.LeaveDays.Add(model);
                            await _context.SaveChangesAsync();
                            try
                            {
                                await LoggerHelper.LogAsync(
                                    _context,
                                    userId: null,
                                    action: "İzin Al(Stajyerler)",
                                    description: $"{internid} ID'li {NickName}  adlı stajyer tarafından izin alınmıştır.(İzin alım: {model.StartDate} İzin Bitiş: {model.EndDate} İzin Türü: {model.LeaveType} İzin Onay Durumu: {model.IzinOnayDurumu} İzin Alım Tarihi: {model.IzinAlimTarihi} ) Stajyer ID'si: {oturumid}",
                                    internId: internid,
                                    adminId: null
                                );
                            }
                            catch (Exception logEx)
                            {
                                ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                                return View(model);
                            }
                            return RedirectToAction("Permission");
                        }
                        catch (Exception ex)
                        {
                            ModelState.AddModelError("", $"Veritabanına kaydetme işlemi sırasında bir hata oluştu: {ex.Message}");
                        }
                    }
                    else
                    {
                        ModelState.AddModelError("", "Kullanıcı kimliği bulunamadı.");
                    }
                }
                if (role == "Admin")
                {

                    var adminId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                    if (!string.IsNullOrEmpty(adminId))
                    {
                        int adminid = int.Parse(adminId);
                        model.AdminId = int.Parse(adminId);
                        try
                        {
                            _context.LeaveDays.Add(model);
                            await _context.SaveChangesAsync();
                            try
                            {
                                await LoggerHelper.LogAsync(
                                    _context,
                                    userId: null,
                                    action: "İzin Al(Adminler)",
                                    description: $"{adminid} ID'li {NickName}  adlı admin tarafından izin alınmıştır.(İzin alım: {model.StartDate} İzin Bitiş: {model.EndDate} İzin Türü: {model.LeaveType} İzin Onay Durumu: {model.IzinOnayDurumu} İzin Alım Tarihi: {model.IzinAlimTarihi} ) Admin ID'si: {oturumid}",
                                    internId: null,
                                    adminId: adminid
                                );
                            }
                            catch (Exception logEx)
                            {
                                ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                                return View(model);
                            }

                            return RedirectToAction("Permission");
                        }
                        catch (Exception ex)
                        {
                            ModelState.AddModelError("", $"Veritabanına kaydetme işlemi sırasında bir hata oluştu: {ex.Message}");
                        }
                    }
                    else
                    {
                        ModelState.AddModelError("", "Kullanıcı kimliği bulunamadı.");
                    }
                }
            }


        }
        else
        {
            ModelState.AddModelError("", "Giriş yapmanız gerekmektedir.");
        }

        return View(model);
    }

    public IActionResult Permission()//OK
    {
        var role = User.FindFirst(ClaimTypes.Role)?.Value;
        if (role == null)
        {
            return RedirectToAction("Login", "User");
        }

        return View();
    }
    public async Task<IActionResult> LogOut()//OK
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        int? oturumid = null;
        var NickName = User.FindFirst(ClaimTypes.Name)?.Value;
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (userIdClaim != null)
        {

            var role = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value.ToString();
            oturumid = int.Parse(userIdClaim);
            if (role == "Admin")
            {

                try
                {
                    await LoggerHelper.LogAsync(
                        _context,
                        userId: null,
                        action: "Çıkış Yap(Adminler)",
                        description: $"{userIdClaim} ID'li, {NickName} kullanıcı adlı admin çıkış yapmıştır.",
                        internId: null,
                        adminId: oturumid
                    );
                }
                catch (Exception logEx)
                {
                    ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");

                }
            }
            if (role == "Intern")
            {

                try
                {
                    await LoggerHelper.LogAsync(
                        _context,
                        userId: null,
                        action: "Çıkış Yap(Stajyerler)",
                        description: $"{userIdClaim} ID'li, {NickName} kullanıcı adlı stajyer çıkış yapmıştır.",
                        internId: oturumid,
                        adminId: null
                    );
                }
                catch (Exception logEx)
                {
                    ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");

                }
            }
            if (role == "User")
            {

                try
                {
                    await LoggerHelper.LogAsync(
                        _context,
                        userId: oturumid,
                        action: "Çıkış Yap(Çalışanlar)",
                        description: $"{userIdClaim} ID'li, {NickName} kullanıcı adlı çalışan çıkış yapmıştır.",
                        internId: null,
                        adminId: null
                    );
                }
                catch (Exception logEx)
                {
                    ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");

                }
            }
        }


        return RedirectToAction("Login", "User");
    }
    public async Task<IActionResult> Profile()//OK

    {
        var kullaniciId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var role = User.FindFirst(ClaimTypes.Role)?.Value;
        if (string.IsNullOrEmpty(kullaniciId))
        {
            return RedirectToAction("Login", "User");
        }
        var profileViewModel = new ProfileViewModel();
        if (role == "User")
        {
            var user = await _context.Users
            .Include(x => x.LeaveDays)


            .FirstOrDefaultAsync(x => x.Id == int.Parse(kullaniciId))
            ;
            if (user != null)
            {
                var leaveDays = user.LeaveDays?
                .OrderByDescending(ld => ld.IzinAlimTarihi)
                .ToList();
                profileViewModel.Users = user;
                Console.WriteLine(user.LeaveDays!.GetType());
                profileViewModel.LeaveDays = leaveDays?.ToList() ?? new List<LeaveDay>();


            }
        }
        else if (role == "Intern")
        {
            var intern = await _context.Interns
            .Include(x => x.LeaveDays)

            .FirstOrDefaultAsync(x => x.Id == int.Parse(kullaniciId));
            if (intern != null)
            {
                var leaveDays = intern.LeaveDays?
                .OrderByDescending(ld => ld.IzinAlimTarihi)
                .ToList();
                profileViewModel.Interns = intern;
                profileViewModel.LeaveDays = leaveDays?.ToList() ?? new List<LeaveDay>();

            }
        }
        else if (role == "Admin")
        {
            var admin = await _context.Admins
            .Include(x => x.LeaveDays)
            .FirstOrDefaultAsync(x => x.Id == int.Parse(kullaniciId));
            if (admin != null)
            {
                var leaveDays = admin.LeaveDays?
                .OrderByDescending(ld => ld.IzinAlimTarihi)
                .ToList();
                profileViewModel.Admins = admin;
                profileViewModel.LeaveDays = leaveDays?.ToList() ?? new List<LeaveDay>();

            }
        }
        return View(profileViewModel);

    }
    public async Task<IActionResult> MyPermissions()//OK
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var userRole = User.FindFirst(ClaimTypes.Role)?.Value;

        if (string.IsNullOrEmpty(userId))
        {
            return RedirectToAction("Login", "User");
        }


        List<LeaveDay> permissions = new List<LeaveDay>();

        if (userRole == "Intern")
        {
            permissions = await _context.LeaveDays
                                        .Where(l => l.InternId == int.Parse(userId))
                                        .OrderByDescending(l => l.IzinAlimTarihi)
                                        .ToListAsync();
        }
        else if (userRole == "User")
        {
            permissions = await _context.LeaveDays
                                        .Where(l => l.UserId == int.Parse(userId))
                                        .OrderByDescending(l => l.IzinAlimTarihi)
                                        .ToListAsync();
        }
        else if (userRole == "Admin")
        {
            permissions = await _context.LeaveDays
                                        .Where(l => l.AdminId == int.Parse(userId))
                                        .OrderByDescending(l => l.IzinAlimTarihi)
                                        .ToListAsync();
        }

        return View(permissions);
    }
    [HttpPost]
    public async Task<IActionResult> DeletePermissions(int id)//OK
    {
        var oturumId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;


        var role = User.FindFirst(ClaimTypes.Role)?.Value;
        var NickName = User.FindFirst(ClaimTypes.Name)?.Value;
        var leaveday = await _context.LeaveDays.FirstOrDefaultAsync(x => x.Id == id);
        if (!string.IsNullOrEmpty(oturumId))
        {
            if (role == "Intern")
            {
                int oturumid = int.Parse(oturumId);

                if (leaveday == null)
                {
                    NotFound();
                }
                else
                {
                    _context.LeaveDays.Remove(leaveday!);
                    await _context.SaveChangesAsync();
                    try
                    {
                        await LoggerHelper.LogAsync(
                            _context,
                            userId: null,
                            action: "İzin Sil(Stajyerler)",
                            description: $"{oturumid} ID'li {NickName} kullanıcı adlı stajyer, {leaveday.Id} ID'li izin kaydını başarıyla silmiştir.(Başlangıç Tarihi:{leaveday.StartDate} Bitiş Tarihi: {leaveday.EndDate} İzin Türü:{leaveday.LeaveType} İzin Alım Tarihi {leaveday.IzinAlimTarihi} İzin Onay Durumu: {leaveday.IzinOnayDurumu})",
                            internId: oturumid,
                            adminId: null
                        );
                    }
                    catch (Exception logEx)
                    {
                        ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                        return View();
                    }
                }


                return RedirectToAction("MyPermissions", "User");
            }
            if (role == "Admin")
            {
                int oturumid = int.Parse(oturumId);

                if (leaveday == null)
                {
                    NotFound();
                }
                else
                {
                    _context.LeaveDays.Remove(leaveday);
                    await _context.SaveChangesAsync();
                    try
                    {
                        await LoggerHelper.LogAsync(
                            _context,
                            userId: null,
                            action: "İzin Sil(Adminler)",
                            description: $"{oturumid} ID'li {NickName} kullanıcı adlı admin, {leaveday.Id} ID'li izin kaydını başarıyla silmiştir.(Başlangıç Tarihi:{leaveday.StartDate} Bitiş Tarihi: {leaveday.EndDate} İzin Türü:{leaveday.LeaveType} İzin Alım Tarihi {leaveday.IzinAlimTarihi} İzin Onay Durumu: {leaveday.IzinOnayDurumu})",
                            internId: null,
                            adminId: oturumid
                        );
                    }
                    catch (Exception logEx)
                    {
                        ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                        return View();
                    }
                }


                return RedirectToAction("MyPermissions", "User");
            }
            if (role == "User")
            {
                int oturumid = int.Parse(oturumId);

                if (leaveday == null)
                {
                    NotFound();
                }
                else
                {
                    _context.LeaveDays.Remove(leaveday);
                    await _context.SaveChangesAsync();
                    try
                    {
                        await LoggerHelper.LogAsync(
                            _context,
                            userId: oturumid,
                            action: "İzin Sil(Çalışanlar)",
                            description: $"{oturumid} ID'li {NickName} kullanıcı adlı çalışan, {leaveday.Id} ID'li izin kaydını başarıyla silmiştir.(Başlangıç Tarihi:{leaveday.StartDate} Bitiş Tarihi: {leaveday.EndDate} İzin Türü:{leaveday.LeaveType} İzin Alım Tarihi {leaveday.IzinAlimTarihi} İzin Onay Durumu: {leaveday.IzinOnayDurumu})",
                            internId: null,
                            adminId: null
                        );
                    }
                    catch (Exception logEx)
                    {
                        ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                        return View();
                    }
                }


                return RedirectToAction("MyPermissions", "User");
            }
        }
        return RedirectToAction(nameof(Login));
    }
    [HttpGet]

    public async Task<IActionResult> UpdatePermissions(int? id)//OK
    {
        if (id == null)
        {
            return NotFound();
        }
        var leaveday = await _context.LeaveDays.FirstOrDefaultAsync(x => x.Id == id);
        if (leaveday == null)
        {
            return NotFound();
        }
        return View(leaveday);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> UpdatePermissions(int id, LeaveDay model)//EN SON BURAYA KADAR LOG KAYDI YAPILDI***********************
    {
        var oturumId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        var role = User.FindFirst(ClaimTypes.Role)?.Value;
        var NickName = User.FindFirst(ClaimTypes.Name)?.Value;
        if (id != model.Id)
        {
            return NotFound();
        }
        if (oturumId == null)
        {
            return RedirectToAction(nameof(Login));
        }

        if (ModelState.IsValid)
        {
            try
            {

                _context.Update(model);
                await _context.SaveChangesAsync();
                if (role == "Admin")
                {
                    int oturumid = int.Parse(oturumId);

                    if (model == null)
                    {
                        NotFound();
                    }
                    else
                    {

                        try
                        {
                            await LoggerHelper.LogAsync(
                                _context,
                                userId: null,
                                action: "İzin Güncelle(Adminler)",
                                description: $"{oturumid} ID'li {NickName} kullanıcı adlı admin, {model.Id} ID'li izin kaydını başarıyla güncellemiştir.(Başlangıç Tarihi:{model.StartDate} Bitiş Tarihi: {model.EndDate} İzin Türü:{model.LeaveType} İzin Alım Tarihi {model.IzinAlimTarihi} İzin Onay Durumu: {model.IzinOnayDurumu})",
                                internId: null,
                                adminId: oturumid
                            );
                        }
                        catch (Exception logEx)
                        {
                            ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                            return View();
                        }
                    }


                    return RedirectToAction("MyPermissions", "User");
                }
                if (role == "User")
                {
                    int oturumid = int.Parse(oturumId);

                    if (model == null)
                    {
                        NotFound();
                    }
                    else
                    {

                        try
                        {
                            await LoggerHelper.LogAsync(
                                _context,
                                userId: oturumid,
                                action: "İzin Güncelle(Çalışanlar)",
                                description: $"{oturumid} ID'li {NickName} kullanıcı adlı çalışan, {model.Id} ID'li izin kaydını başarıyla güncellemiştir.(Başlangıç Tarihi:{model.StartDate} Bitiş Tarihi: {model.EndDate} İzin Türü:{model.LeaveType} İzin Alım Tarihi {model.IzinAlimTarihi} İzin Onay Durumu: {model.IzinOnayDurumu})",
                                internId: null,
                                adminId: null
                            );
                        }
                        catch (Exception logEx)
                        {
                            ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                            return View();
                        }
                    }


                    return RedirectToAction("MyPermissions", "User");
                }
                if (role == "Intern")
                {
                    int oturumid = int.Parse(oturumId);

                    if (model == null)
                    {
                        NotFound();
                    }
                    else
                    {

                        try
                        {
                            await LoggerHelper.LogAsync(
                                _context,
                                userId: null,
                                action: "İzin Güncelle(Stajyerler)",
                                description: $"{oturumid} ID'li {NickName} kullanıcı adlı stajyer, {model.Id} ID'li izin kaydını başarıyla güncellemiştir.(Başlangıç Tarihi:{model.StartDate} Bitiş Tarihi: {model.EndDate} İzin Türü:{model.LeaveType} İzin Alım Tarihi {model.IzinAlimTarihi} İzin Onay Durumu: {model.IzinOnayDurumu})",
                                internId: oturumid,
                                adminId: null
                            );
                        }
                        catch (Exception logEx)
                        {
                            ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                            return View();
                        }
                    }


                    return RedirectToAction("MyPermissions", "User");
                }
                return RedirectToAction("MyPermissions", "User");
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!_context.LeaveDays.Any(o => o.Id == model.Id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }
        }

        return View(model);
    }

    public async Task<IActionResult> AllPermissions()
    {
        var role = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;
        if (User.Identity!.IsAuthenticated == false)
        {
            if (role != "Admin")
            {
                return RedirectToAction("Login", "User");
            }
        }


        var permissions = await _context.LeaveDays
                                   .Include(l => l.Users)
                                   .Include(l => l.Interns)
                                   .Include(l => l.Admins)
                                   .OrderByDescending(l => l.IzinAlimTarihi)
                                   .ToListAsync();


        return View(permissions);
    }
    [HttpPost]
    public async Task<IActionResult> OnayIzin(int id)

    {
        var permission = await _context.LeaveDays.FirstOrDefaultAsync(x => x.Id == id);
        if (permission == null)
        {
            return NotFound();
        }
        int? oturumid = null;
        var NickName = User.FindFirst(ClaimTypes.Name)?.Value;
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (userIdClaim != null)
        {
            var role = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;
            oturumid = int.Parse(userIdClaim);

            permission.IzinOnayDurumu = "Onaylandı";
            _context.LeaveDays.Update(permission);
            await _context.SaveChangesAsync();
            try
            {
                await LoggerHelper.LogAsync(
                    _context,
                    userId: null,
                    action: "İzin Onay",
                    description: $"{permission.Id} ID'li izin kaydı {NickName} tarafından başarıyla onaylanmıştır.(İzin alım: {permission.StartDate} İzin Bitiş: {permission.EndDate} İzin Türü: {permission.LeaveType} İzin Onay Durumu: {permission.IzinOnayDurumu} İzin Alım Tarihi: {permission.IzinAlimTarihi} )",
                    internId: null,
                    adminId: oturumid
                );
            }
            catch (Exception logEx)
            {
                ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                return View(permission);
            }
        }

        return RedirectToAction("AllPermissions", "User");
    }
    [HttpPost]
    public async Task<IActionResult> RedIzin(int id)
    {
        var permission = await _context.LeaveDays.FirstOrDefaultAsync(x => x.Id == id)
        ;
        if (permission == null)
        {
            return NotFound();
        }
        int? oturumid = null;
        var NickName = User.FindFirst(ClaimTypes.Name)?.Value;
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (userIdClaim != null)
        {
            var role = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;
            oturumid = int.Parse(userIdClaim);

            permission.IzinOnayDurumu = "Reddedildi";
            _context.LeaveDays.Update(permission);
            await _context.SaveChangesAsync();
            try
            {
                await LoggerHelper.LogAsync(
                    _context,
                    userId: null,
                    action: "İzin Red",
                    description: $"{permission.Id} ID'li izin kaydı {NickName} tarafından başarıyla reddedilmiştir.(İzin alım: {permission.StartDate} İzin Bitiş: {permission.EndDate} İzin Türü: {permission.LeaveType} İzin Onay Durumu: {permission.IzinOnayDurumu} İzin Alım Tarihi: {permission.IzinAlimTarihi} )",
                    internId: null,
                    adminId: oturumid
                );
            }
            catch (Exception logEx)
            {
                ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                return View(permission);
            }
        }

        return RedirectToAction("AllPermissions", "User");
    }

    [HttpPost]
    public async Task<IActionResult> DeleteAllPermissions(int id)

    {


        var permission = await _context.LeaveDays
                                   .Include(l => l.Users)
                                   .Include(l => l.Interns)
                                   .Include(l => l.Admins)
                                   .FirstOrDefaultAsync(x => x.Id == id);
        if (permission == null)
        {
            return NotFound();
        }

        int? oturumid = null;
        var NickName = User.FindFirst(ClaimTypes.Name)?.Value;
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;



        if (permission.Admins != null)
        {
            if (userIdClaim != null)
            {

                var role = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;
                oturumid = int.Parse(userIdClaim);


                _context.LeaveDays.Remove(permission);
                await _context.SaveChangesAsync();
                try
                {
                    await LoggerHelper.LogAsync(
                        _context,
                        userId: null,
                        action: "Tüm İzinler İzin Sil(Admin)",
                        description: $"{permission.Id} ID'li izin kaydı {NickName} tarafından başarıyla silinmiştir.(İzin alım: {permission.StartDate} İzin Bitiş: {permission.EndDate} İzin Türü: {permission.LeaveType} İzin Onay Durumu: {permission.IzinOnayDurumu} İzin Alım Tarihi: {permission.IzinAlimTarihi} //İzni silinen; Id: {permission.Admins.Id} Adı: {permission.Admins.AdSoyad} E-mail: {permission.Admins.Email}Şifre: {permission.Admins.Password} )",
                        internId: null,
                        adminId: oturumid
                    );
                }
                catch (Exception logEx)
                {
                    ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                    return View(permission);
                }
            }
        }

        else if (permission.Interns != null)
        {
            if (userIdClaim != null)
            {

                var role = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;
                oturumid = int.Parse(userIdClaim);


                _context.LeaveDays.Remove(permission);
                await _context.SaveChangesAsync();
                try
                {
                    await LoggerHelper.LogAsync(
                        _context,
                        userId: null,
                        action: "Tüm İzinler İzin Sil(Stajyer)",
                        description: $"{permission.Id} ID'li izin kaydı {NickName} tarafından başarıyla silinmiştir.(İzin alım: {permission.StartDate} İzin Bitiş: {permission.EndDate} İzin Türü: {permission.LeaveType} İzin Onay Durumu: {permission.IzinOnayDurumu} İzin Alım Tarihi: {permission.IzinAlimTarihi} İzni silinen; Id: {permission.Interns.Id} Adı: {permission.Interns.AdSoyad} E-mail: {permission.Interns.Email} Telefon: {permission.Interns.Phone})",
                        internId: null,
                        adminId: oturumid
                    );
                }
                catch (Exception logEx)
                {
                    ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                    return View(permission);
                }
            }
        }
        else if (permission.Users != null)
        {
            if (userIdClaim != null)
            {

                var role = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;
                oturumid = int.Parse(userIdClaim);


                _context.LeaveDays.Remove(permission);
                await _context.SaveChangesAsync();
                try
                {
                    await LoggerHelper.LogAsync(
                        _context,
                        userId: null,
                        action: "Tüm İzinler İzin Sil(Çalışan)",
                        description: $"{permission.Id} ID'li izin kaydı {NickName} tarafından başarıyla silinmiştir.(İzin alım: {permission.StartDate} İzin Bitiş: {permission.EndDate} İzin Türü: {permission.LeaveType} İzin Onay Durumu: {permission.IzinOnayDurumu} İzin Alım Tarihi: {permission.IzinAlimTarihi} İzni silinen; Id: {permission.Users.Id} Adı: {permission.Users.AdSoyad} E-mail: {permission.Users.Email} Telefon: {permission.Users.Phone})",
                        internId: null,
                        adminId: oturumid
                    );
                }
                catch (Exception logEx)
                {
                    ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                    return View(permission);
                }
            }
        }
        else
        {
            return NotFound();
        }


        return RedirectToAction("AllPermissions", "User");
    }
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> UpdateAllPermissions(int id, LeaveDay model)
    {
        if (id != model.Id)
        {
            return NotFound();
        }

        if (ModelState.IsValid)
        {
            try
            {

                _context.Update(model);
                await _context.SaveChangesAsync();
                int? oturumid = null;
                var NickName = User.FindFirst(ClaimTypes.Name)?.Value;
                var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;



                if (model.Admins != null)
                {
                    if (userIdClaim != null)
                    {

                        var role = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;
                        oturumid = int.Parse(userIdClaim);

                        try
                        {
                            await LoggerHelper.LogAsync(
                                _context,
                                userId: null,
                                action: "Tüm İzinler İzin Güncelle(Adminler)",
                                description: $"{model.Id} ID'li izin kaydı {NickName} tarafından başarıyla güncellenmiştir.(İzin alım: {model.StartDate} İzin Bitiş: {model.EndDate} İzin Türü: {model.LeaveType} İzin Onay Durumu: {model.IzinOnayDurumu} İzin Alım Tarihi: {model.IzinAlimTarihi}İzin güncellenen kullanıcının ; Adı: {model.Admins.AdSoyad} Kullanıcı Adı: {model.Admins.NickName} Mail: {model.Admins.Email} )",
                                internId: null,
                                adminId: oturumid
                            );
                        }
                        catch (Exception logEx)
                        {
                            ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                            return View(model);
                        }
                    }
                    return RedirectToAction("AllPermissions", "User");
                }
                if (model.Users != null)
                {
                    if (userIdClaim != null)
                    {

                        var role = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;
                        oturumid = int.Parse(userIdClaim);

                        try
                        {
                            await LoggerHelper.LogAsync(
                                _context,
                                userId: null,
                                action: "Tüm İzinler İzin Güncelle(Çalışanlar)",
                                description: $"{model.Id} ID'li izin kaydı {NickName} tarafından başarıyla güncellenmiştir.(İzin alım: {model.StartDate} İzin Bitiş: {model.EndDate} İzin Türü: {model.LeaveType} İzin Onay Durumu: {model.IzinOnayDurumu} İzin Alım Tarihi: {model.IzinAlimTarihi}İzin güncellenen kullanıcının ; Adı: {model.Users.AdSoyad} Kullanıcı Adı: {model.Users.NickName} Mail: {model.Users.Email} Bölüm : {model.Users.Position} Telefon: {model.Users.Phone})",
                                internId: null,
                                adminId: oturumid
                            );
                        }
                        catch (Exception logEx)
                        {
                            ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                            return View(model);
                        }
                    }
                    return RedirectToAction("AllPermissions", "User");
                }
                if (model.Interns != null)
                {
                    if (userIdClaim != null)
                    {

                        var role = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;
                        oturumid = int.Parse(userIdClaim);

                        try
                        {
                            await LoggerHelper.LogAsync(
                                _context,
                                userId: null,
                                action: "Tüm İzinler İzin Güncelle(Stajyerler)",
                                description: $"{model.Id} ID'li izin kaydı {NickName} tarafından başarıyla güncellenmiştir.(İzin alım: {model.StartDate} İzin Bitiş: {model.EndDate} İzin Türü: {model.LeaveType} İzin Onay Durumu: {model.IzinOnayDurumu} İzin Alım Tarihi: {model.IzinAlimTarihi}İzin güncellenen kullanıcının ; Adı: {model.Interns.AdSoyad} Kullanıcı Adı: {model.Interns.NickName} Mail: {model.Interns.Email} Bölüm : {model.Interns.Position} Telefon: {model.Interns.Phone} Okul: {model.Interns.Okul})",
                                internId: null,
                                adminId: oturumid
                            );
                        }
                        catch (Exception logEx)
                        {
                            ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                            return View(model);
                        }
                    }
                    return RedirectToAction("AllPermissions", "User");
                }
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!_context.LeaveDays.Any(o => o.Id == model.Id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }
        }

        return View(model);
    }
    [HttpGet]
    public async Task<IActionResult> UpdateAllPermissions(int? id)
    {
        if (id == null)
        {
            return NotFound();
        }
        var leaveday = await _context.LeaveDays
        .Include(l => l.Users)
        .Include(l => l.Interns)
        .Include(l => l.Admins)
        .FirstOrDefaultAsync(x => x.Id == id);
        if (leaveday == null)
        {
            return NotFound();
        }
        return View(leaveday);
    }

    [HttpPost]
    public async Task<IActionResult> DuyuruYap(Duyuru model)
    {



        if (ModelState.IsValid)
        {
            var adminId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (adminId == null)
            {
                return NotFound();
            }
            model.AdminId = int.Parse(adminId);
            model.DuyuruTarih = DateTime.Now;
            _context.Duyurus.Add(model);
            await _context.SaveChangesAsync();
            int? oturumid = null;
            var NickName = User.FindFirst(ClaimTypes.Name)?.Value;
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;




            if (userIdClaim != null)
            {

                var role = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;
                oturumid = int.Parse(userIdClaim);

                try
                {
                    await LoggerHelper.LogAsync(
                        _context,
                        userId: null,
                        action: "Duyuru Yap",
                        description: $"{model.Id} ID'li duyuru  {NickName} tarafından başarıyla yapılmıştır.(Duyuru Konu: {model.Konu} Duyuru İçerik: {model.Icerik} Duyuru Tarihi: {model.DuyuruTarih} Duyuru Yapan Admin Id: {model.AdminId} )",
                        internId: null,
                        adminId: oturumid
                    );
                }
                catch (Exception logEx)
                {
                    ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                    return View(model);
                }
            }


            return RedirectToAction(nameof(Duyuru));
        }

        return View(model);


    }
    public IActionResult DuyuruYap()
    {
        var role = User.FindFirst(ClaimTypes.Role)?.Value;
        if (role == "Admin")
        {


            return View();
        }
        return RedirectToAction("Login", "User");

    }
    public async Task<IActionResult> Duyuru()
    {
        var role = User.FindFirst(ClaimTypes.Role)?.Value;
        if (role != null)
        {



            bool isAdmin = User.IsInRole("Admin");
            var duyuru = await _context.Duyurus

                                  .Include(l => l.Admins)
                                  .OrderByDescending(l => l.DuyuruTarih)
                                  .ToListAsync();


            ViewBag.IsAdmin = isAdmin;//SAYFAYA İSADMİN DEĞİŞKENİNİ GÖNDERMEK İÇİN YAPIYORUZ ÖNEMLİ!!!!!!!!!!!!!
            return View(duyuru);
        }
        else
        {
            return RedirectToAction("Login", "User");
        }

    }
    [HttpPost]
    public async Task<IActionResult> DuyuruDelete(int id)

    {

        var duyuru = await _context.Duyurus.FirstOrDefaultAsync(x => x.Id == id);
        if (duyuru == null)
        {
            return NotFound();
        }
        _context.Duyurus.Remove(duyuru!);
        await _context.SaveChangesAsync();
        int? oturumid = null;
        var NickName = User.FindFirst(ClaimTypes.Name)?.Value;
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;




        if (userIdClaim != null)
        {

            var role = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;
            oturumid = int.Parse(userIdClaim);

            try
            {
                await LoggerHelper.LogAsync(
                    _context,
                    userId: null,
                    action: "Duyuru Sil",
                    description: $"{duyuru.Id} ID'li duyuru  {NickName} tarafından başarıyla silinmiştir.(Duyuru Konu: {duyuru.Konu} Duyuru İçerik: {duyuru.Icerik} Duyuru Tarihi: {duyuru.DuyuruTarih} Duyuru Yapan Admin Id: {duyuru.AdminId} )",
                    internId: null,
                    adminId: oturumid
                );
            }
            catch (Exception logEx)
            {
                ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                return View(duyuru);
            }
        }

        return RedirectToAction("Duyuru", "User");
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DuyuruUpdate(int id, Duyuru model)
    {
        if (id != model.Id)
        {
            return NotFound();
        }

        if (ModelState.IsValid)
        {
            try
            {
                model.DuyuruTarih = DateTime.Now;
                _context.Update(model);
                await _context.SaveChangesAsync();
                int? oturumid = null;
                var NickName = User.FindFirst(ClaimTypes.Name)?.Value;
                var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;




                if (userIdClaim != null)
                {

                    var role = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;
                    oturumid = int.Parse(userIdClaim);

                    try
                    {
                        await LoggerHelper.LogAsync(
                            _context,
                            userId: null,
                            action: "Duyuru Düzenle",
                            description: $"{model.Id} ID'li duyuru  {NickName} tarafından başarıyla düzenlenmiştir.(Duyuru Konu: {model.Konu} Duyuru İçerik: {model.Icerik} Duyuru Tarihi: {model.DuyuruTarih} Duyuru Yapan Admin Id: {model.AdminId} )",
                            internId: null,
                            adminId: oturumid
                        );
                    }
                    catch (Exception logEx)
                    {
                        ModelState.AddModelError("", $"Loglama sırasında bir hata oluştu: {logEx.Message}");
                        return View(model);
                    }
                }
                return RedirectToAction("Duyuru", "User");
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!_context.Duyurus.Any(o => o.Id == model.Id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }
        }

        return View(model);
    }
    [HttpGet]
    public async Task<IActionResult> DuyuruUpdate(int? id)
    {
        if (id == null)
        {
            return NotFound();
        }
        var duyuru = await _context.Duyurus.FirstOrDefaultAsync(x => x.Id == id);
        if (duyuru == null)
        {
            return NotFound();
        }
        return View(duyuru);
    }




}

//ALPARSLAN TÜRKOĞLU 16-09-2024  // 29-12-2024 STAJYER



