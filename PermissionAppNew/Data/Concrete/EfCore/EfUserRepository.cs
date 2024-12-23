using PermissionAppNew.Data.Abstract;


namespace PermissionAppNew.Data.Concrete
{
    public class EfUserRepository : IUserRepository
    {
        private DataContext _context;
        public EfUserRepository(DataContext context)
        {
            _context = context;
        }
        public IQueryable<User> Users => _context.Users;

        public void CreateUser(User user)
        {
            _context.Users.Add(user);
            _context.SaveChanges();

        }
    }
}

