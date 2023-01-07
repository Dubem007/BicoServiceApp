using BicoAuthService.Data.DbContext;
using BicoAuthService.Entities.Identity;
using BicoAuthService.Interface;

namespace BicoAuthService.Services
{
    public class UserRepository : Repository<User>, IUserRepository
    {
        public UserRepository(AppDbContext appDbContext) : base(appDbContext)
        {
        }
    }
}
