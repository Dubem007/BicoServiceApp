using System.Linq.Expressions;

namespace BicoAuthService.Interface
{
    public interface IRepository<TEntity> where TEntity : class
    {
        IQueryable<TEntity> FindAll(bool trackChanges);
        IQueryable<TEntity> FindByCondition(Expression<Func<TEntity, bool>> expression, bool trackChanges);
        Task<TEntity> FirstOrDefaultAsync(Expression<Func<TEntity, bool>> expression, bool trackChanges);
        IQueryable<TEntity> Get(Expression<Func<TEntity, bool>> predicate);
        IQueryable<TEntity> QueryAll(Expression<Func<TEntity, bool>> predicate = null);
        Task CreateAsync(TEntity entity);
        void Update(TEntity entity);
        void Delete(TEntity entity);
        Task<int> CountAsync(Expression<Func<TEntity, bool>> predicate);
        void UpdateRange(IEnumerable<TEntity> entity);
        Task<TEntity> GetByIdAsync(Guid id);
        Task<bool> ExistsAsync(Expression<Func<TEntity, bool>> predicate);
        void DeleteRange(IEnumerable<TEntity> entity);
        Task<IEnumerable<TEntity>> GetAllAsync();
        Task AddRangeAsync(IEnumerable<TEntity> entity);
        Task<int> SaveChangesAsync();
    }
}
