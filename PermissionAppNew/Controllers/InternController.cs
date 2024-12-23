using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;


public class InternController : Controller
{
    private readonly DataContext _context;

    public InternController(DataContext context)
    {
        _context = context;
    }

    // GET: Interns/Create
    public IActionResult Create()
    {
        if (User.Identity!.IsAuthenticated)
        {
            return RedirectToAction("Permission", "User");

        }
        return View();
    }

    // POST: Interns/Create
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(Intern intern)
    {
        if (ModelState.IsValid)
        {
            // Veriyi eklerken sorun olup olmadığını kontrol etmek için bir log ekleyebiliriz
            _context.Interns.Add(intern);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        // Eğer ModelState geçersizse, aynı sayfayı hatalarla birlikte gösterir
        return View(intern);
    }

    // GET: Interns
    public async Task<IActionResult> InternList()
    {
        if (User.Identity!.IsAuthenticated)
        {
            return RedirectToAction("InternList", "Intern");

        }
        return View(await _context.Interns.ToListAsync());
    }

    // GET: Interns/Details/5
    public async Task<IActionResult> Details(int? id)
    {
        if (User.Identity!.IsAuthenticated)
        {
            return RedirectToAction("Permission", "User");

        }
        if (id == null)
        {
            return NotFound();
        }

        var intern = await _context.Interns
            .FirstOrDefaultAsync(m => m.Id == id);
        if (intern == null)
        {
            return NotFound();
        }

        return View(intern);
    }

    // GET: Interns/Delete/5
    public async Task<IActionResult> Delete(int? id)
    {
        if (User.Identity!.IsAuthenticated)
        {
            return RedirectToAction("Permission", "User");

        }
        if (id == null)
        {
            return NotFound();
        }

        var intern = await _context.Interns
            .FirstOrDefaultAsync(m => m.Id == id);
        if (intern == null)
        {
            return NotFound();
        }

        return View(intern);
    }

    // POST: Interns/Delete/5
    [HttpPost, ActionName("Delete")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteConfirmed(int id)
    {
        var intern = await _context.Interns.FindAsync(id);
        if (intern == null)
        {
            return NotFound(); // Eğer intern bulunamazsa hata sayfası döner
        }
        _context.Interns.Remove(intern);
        await _context.SaveChangesAsync();
        return RedirectToAction(nameof(Index));
    }

    private bool InternExists(int id)
    {
        return _context.Interns.Any(e => e.Id == id);
    }
}
