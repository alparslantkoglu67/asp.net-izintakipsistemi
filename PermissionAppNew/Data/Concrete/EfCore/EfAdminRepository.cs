using PermissionAppNew.Data.Abstract;


namespace PermissionAppNew.Data.Concrete
{
    public class EfAdminRepository : IAdminRepository
    {
        private DataContext _context;
        public EfAdminRepository(DataContext context)
        {
            _context = context;
        }
        public IQueryable<Admin> Admins => _context.Admins;

        public void CreateAdmin(Admin admin)
        {
            _context.Admins.Add(admin);
            _context.SaveChanges();

        }
    }
}