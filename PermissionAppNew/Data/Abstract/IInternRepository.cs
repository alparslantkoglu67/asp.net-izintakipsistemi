namespace PermissionAppNew.Data.Abstract
{
    public interface IInternRepository
    {
        IQueryable<Intern> Interns { get; }
        void CreateIntern(Intern Intern);
    }
}