namespace PermissionAppNew.Data.Abstract
{
    public interface IAdminRepository
    {
        IQueryable<Admin> Admins { get; }
        void CreateAdmin(Admin Admin);
    }
}