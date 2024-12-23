using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using PermissionAppNew.Data.Abstract;
using PermissionAppNew.Models;
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
    public IActionResult Login()
    {
        if (User.Identity!.IsAuthenticated)
        {
            return RedirectToAction("Duyuru", "User");

        }
        return View();
    }
    [HttpPost]
    public async Task<IActionResult> Login(LoginViewModel model)
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

                return RedirectToAction("Duyuru", "User");
            }

            else
            {
                ModelState.AddModelError("", "Kullanıcı adı veya şifre yanlış");
            }
            return View(model);
        }
        return View(model);


    }

    public IActionResult CreateUser()
    {
        return View();

    }
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CreateUser(User model)
    {
        if (ModelState.IsValid)
        {
            try
            {
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
                            action: "CreateUserByAdmin",
                            description: model.NickName + " adlı kayıt " + role + " tarafından oluşturulmuştur. Çalışan ID'si: " + model.Id,
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
                            action: "CreateUser",
                            description: model.NickName + " adlı kayıt " + model.NickName + " tarafından oluşturulmuştur. Çalışan ID'si: " + model.Id,
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


    public IActionResult CreateIntern()
    {

        return View();


    }
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CreateIntern(Intern model)
    {
        if (ModelState.IsValid)
        {
            try
            {
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
                            action: "CreateInternByAdmin",
                            description: model.NickName + " adlı kayıt " + role + " tarafından oluşturulmuştur. Stajyer ID'si: " + model.Id,
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
                            action: "CreateIntern",
                            description: model.NickName + " adlı kayıt " + model.NickName + " tarafından oluşturulmuştur. Stajyer ID'si: " + model.Id,
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





    public async Task<IActionResult> UserList()
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
    public async Task<IActionResult> DeleteUserList(int id)

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
                            action: "DeleteUserByAdmin",
                            description: user.NickName + " adlı kayıt " + role + " tarafından silinmiştir. Çalışan ID'si: " + user.Id,
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
    public async Task<IActionResult> UpdateUserList(int? id)
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
    public async Task<IActionResult> UpdateUserList(int id, User model)
    {
        if (id != model.Id)
        {
            return NotFound();
        }

        if (ModelState.IsValid)
        {
            int? oturumcuId = null;
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
                            action: "UpdateUserByAdmin",
                            description: model.NickName + " adlı kayıt " + role + " tarafından düzenlenmiştir. Çalışan ID'si: " + model.Id,
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

    public async Task<IActionResult> InternList()
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
    public async Task<IActionResult> DeleteInternList(int id)
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
                            action: "DeleteInternByAdmin",
                            description: intern.NickName + " adlı kayıt " + role + " tarafından silinmiştir. Stajyer ID'si: " + intern.Id,
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
    public async Task<IActionResult> UpdateInternList(int? id)
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
    public async Task<IActionResult> UpdateInternList(int id, Intern model)
    {
        if (id != model.Id)
        {
            return NotFound();
        }

        if (ModelState.IsValid)
        {
            int? oturumcuId = null;
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
                            action: "UpdateInternByAdmin",
                            description: model.NickName + " adlı kayıt " + role + " tarafından düzenlenmiştir. Stajyer ID'si: " + model.Id,
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
    public async Task<IActionResult> Permission(LeaveDay model)
    {
        var role = User.FindFirst(ClaimTypes.Role)?.Value;
        var NickName = User.FindFirst(ClaimTypes.Name)?.Value;


        if (User.Identity != null && User.Identity.IsAuthenticated)
        {
            if (ModelState.IsValid)
            {
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
                                    action: "PermissionByUser",
                                    description: $"{userid} ID'li {NickName}  adlı kullanıcı tarafından izin alınmıştır.(İzin alım: {model.StartDate} İzin Bitiş: {model.EndDate} İzin Türü: {model.LeaveType} İzin Onay Durumu: {model.IzinOnayDurumu} İzin Alım Tarihi: {model.IzinAlimTarihi} ) Çalışan ID'si: {model.UserId}",
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
                                    action: "PermissionByIntern",
                                    description: $"{internid} ID'li {NickName}  adlı stajyer tarafından izin alınmıştır.(İzin alım: {model.StartDate} İzin Bitiş: {model.EndDate} İzin Türü: {model.LeaveType} İzin Onay Durumu: {model.IzinOnayDurumu} İzin Alım Tarihi: {model.IzinAlimTarihi} ) Stajyer ID'si: {model.UserId}",
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
                                    action: "PermissionByAdmin",
                                    description: $"{adminid} ID'li {NickName}  adlı admin tarafından izin alınmıştır.(İzin alım: {model.StartDate} İzin Bitiş: {model.EndDate} İzin Türü: {model.LeaveType} İzin Onay Durumu: {model.IzinOnayDurumu} İzin Alım Tarihi: {model.IzinAlimTarihi} ) Admin ID'si: {model.UserId}",
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

    public IActionResult Permission()
    {
        var role = User.FindFirst(ClaimTypes.Role)?.Value;
        if (role != null)
            return View();

        return View();
    }
    public async Task<IActionResult> LogOut()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        return RedirectToAction("Login", "User");
    }
    public async Task<IActionResult> Profile()

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
    public async Task<IActionResult> MyPermissions()
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
    public async Task<IActionResult> DeletePermissions(int id)
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
                            action: "DeletePermissionByIntern",
                            description: $"{oturumid} ID'li {NickName} kullanıcı adlı stajyer, {leaveday.Id} ID'li kaydı başarıyla silmiştir.(Başlangıç Tarihi:{leaveday.StartDate} Bitiş Tarihi: {leaveday.EndDate} İzin Türü:{leaveday.LeaveType} İzin Alım Tarihi {leaveday.IzinAlimTarihi} İzin Onay Durumu: {leaveday.IzinOnayDurumu})",
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
                            action: "DeletePermissionByAdmin",
                            description: $"{oturumid} ID'li {NickName} kullanıcı adlı admin, {leaveday.Id} ID'li kaydı başarıyla silmiştir.(Başlangıç Tarihi:{leaveday.StartDate} Bitiş Tarihi: {leaveday.EndDate} İzin Türü:{leaveday.LeaveType} İzin Alım Tarihi {leaveday.IzinAlimTarihi} İzin Onay Durumu: {leaveday.IzinOnayDurumu})",
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
                            action: "DeletePermissionByUser",
                            description: $"{oturumid} ID'li {NickName} kullanıcı adlı çalışan, {leaveday.Id} ID'li kaydı başarıyla silmiştir.(Başlangıç Tarihi:{leaveday.StartDate} Bitiş Tarihi: {leaveday.EndDate} İzin Türü:{leaveday.LeaveType} İzin Alım Tarihi {leaveday.IzinAlimTarihi} İzin Onay Durumu: {leaveday.IzinOnayDurumu})",
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

    public async Task<IActionResult> UpdatePermissions(int? id)
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
    public async Task<IActionResult> UpdatePermissions(int id, LeaveDay model)
    {
        var oturumId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        var role = User.FindFirst(ClaimTypes.Role)?.Value;
        var NickName = User.FindFirst(ClaimTypes.Name)?.Value;
        if (id != model.Id)
        {
            return NotFound();
        }

        if (ModelState.IsValid)
        {
            try
            {
                model.IzinAlimTarihi = DateTime.Now;
                _context.Update(model);
                await _context.SaveChangesAsync();
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



        var permissions = await _context.LeaveDays
                                   .Include(l => l.Users)
                                   .Include(l => l.Interns)
                                   .Include(l => l.Admins)
                                   .OrderByDescending(l => l.IzinAlimTarihi)
                                   .ToListAsync();


        return View(permissions);
    }
    [HttpPost]
    public async Task<IActionResult> IzinOnayAllPermissions(int id, LeaveDay model)

    {
        var permission = await _context.LeaveDays.FirstOrDefaultAsync(x => x.Id == id);
        if (permission == null)
        {
            return NotFound();
        }

        permission.IzinOnayDurumu = "Onaylandı";
        _context.LeaveDays.Update(permission);
        await _context.SaveChangesAsync();

        return RedirectToAction("AllPermissions", "User");
    }
    [HttpPost]
    public async Task<IActionResult> IzinRedAllPermissions(int id)
    {
        var permission = await _context.LeaveDays.FirstOrDefaultAsync(x => x.Id == id);
        if (permission == null)
        {
            return NotFound();
        }

        permission.IzinOnayDurumu = "Reddedildi";
        _context.LeaveDays.Update(permission);
        await _context.SaveChangesAsync();

        return RedirectToAction("AllPermissions", "User");
    }

    [HttpPost]
    public async Task<IActionResult> DeleteAllPermissions(int id)

    {

        var permission = await _context.LeaveDays.FirstOrDefaultAsync(x => x.Id == id);
        if (permission == null)
        {
            NotFound();
        }
        _context.LeaveDays.Remove(permission!);
        await _context.SaveChangesAsync();
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
                return RedirectToAction("AllPermissions", "User");
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
            NotFound();
        }
        _context.Duyurus.Remove(duyuru!);
        await _context.SaveChangesAsync();
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





