using BicoAuthService.Data.DbContext;
using BicoAuthService.Entities;
using BicoAuthService.Interface;

namespace BicoAuthService.Services
{
    public class UserActivityService : Repository<UserActivity>, IUserActivityRepository
    {
        public UserActivityService(AppDbContext context) : base(context)
        {

        }
    }
}
