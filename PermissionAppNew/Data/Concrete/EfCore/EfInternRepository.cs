using PermissionAppNew.Data.Abstract;


namespace PermissionAppNew.Data.Concrete
{
    public class EfInternRepository : IInternRepository
    {
        private DataContext _context;
        public EfInternRepository(DataContext context)
        {
            _context = context;
        }
        public IQueryable<Intern> Interns => _context.Interns;

        public void CreateIntern(Intern intern)
        {
            _context.Interns.Add(intern);
            _context.SaveChanges();

        }
    }
}