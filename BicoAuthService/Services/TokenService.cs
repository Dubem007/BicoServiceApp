using BicoAuthService.Data.DbContext;
using BicoAuthService.Entities;
using BicoAuthService.Interface;

namespace BicoAuthService.Services
{
    public class TokenService : Repository<Token>, IToken
    {
        public TokenService(AppDbContext context) : base(context)
        {
        }
    }
}
