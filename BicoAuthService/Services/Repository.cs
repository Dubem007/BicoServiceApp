using BicoAuthService.Data.DbContext;
using BicoAuthService.Interface;
using Microsoft.EntityFrameworkCore;
using System.Linq.Expressions;

namespace BicoAuthService.Services
{
    public abstract class Repository<TEntity> : IRepository<TEntity> where TEntity : class
    {
        protected AppDbContext RepositoryContext;

        public Repository(AppDbContext repositoryContext) => RepositoryContext = repositoryContext;

        public IQueryable<TEntity> FindAll(bool trackChanges) =>
            !trackChanges ? RepositoryContext.Set<TEntity>().AsNoTracking() : RepositoryContext.Set<TEntity>();

        public IQueryable<TEntity> FindByCondition(Expression<Func<TEntity, bool>> expression, bool trackChanges) =>
            !trackChanges ?
                RepositoryContext.Set<TEntity>().Where(expression).AsNoTracking() :
                RepositoryContext.Set<TEntity>().Where(expression);

        public Task<TEntity> FirstOrDefaultAsync(Expression<Func<TEntity, bool>> expression, bool trackChanges) =>
            !trackChanges ?
                RepositoryContext.Set<TEntity>().AsNoTracking().FirstOrDefaultAsync(expression) :
                RepositoryContext.Set<TEntity>().FirstOrDefaultAsync(expression);

        public virtual IQueryable<TEntity> QueryAll(Expression<Func<TEntity, bool>> predicate = null)
        {
            return predicate == null ? RepositoryContext.Set<TEntity>() : RepositoryContext.Set<TEntity>().Where(predicate);
        }
        public virtual IQueryable<TEntity> Get(Expression<Func<TEntity, bool>> predicate = null)
        {
            return predicate == null ? RepositoryContext.Set<TEntity>() : RepositoryContext.Set<TEntity>().Where(predicate);
        }
        public virtual async Task<TEntity> GetByIdAsync(Guid id)
        {
            var entity = await RepositoryContext.Set<TEntity>().FindAsync(id);

            if (entity == null) return null;

            return entity;
        }
        public virtual async Task<int> CountAsync(Expression<Func<TEntity, bool>> predicate)
        {
            return await RepositoryContext.Set<TEntity>().CountAsync(predicate);
        }

        public virtual async Task<bool> ExistsAsync(Expression<Func<TEntity, bool>> predicate)
        {
            return await RepositoryContext.Set<TEntity>().AnyAsync(predicate);
        }
        public virtual void UpdateRange(IEnumerable<TEntity> entity)
        {
            RepositoryContext.Set<TEntity>().UpdateRange(entity);
        }

        public async Task<IEnumerable<TEntity>> GetAllAsync() =>

             await RepositoryContext.Set<TEntity>().AsNoTracking().ToListAsync();

        public async Task CreateAsync(TEntity entity) =>
            await RepositoryContext.Set<TEntity>().AddAsync(entity);

        public void Update(TEntity entity) =>
            RepositoryContext.Set<TEntity>().Update(entity);

        public void Delete(TEntity entity) =>
            RepositoryContext.Set<TEntity>().Remove(entity);

        public void DeleteRange(IEnumerable<TEntity> entity)
        {
            if (entity == null) throw new ArgumentNullException(nameof(entity));

            RepositoryContext.Set<TEntity>().RemoveRange(entity);
        }

        public virtual async Task AddRangeAsync(IEnumerable<TEntity> entity)
        {
            if (entity == null) throw new ArgumentNullException(nameof(entity));

            await RepositoryContext.Set<TEntity>().AddRangeAsync(entity);
        }

        public async Task<int> SaveChangesAsync() => await RepositoryContext.SaveChangesAsync();
    }
}
