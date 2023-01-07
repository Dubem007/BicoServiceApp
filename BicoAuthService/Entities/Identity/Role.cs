using Microsoft.AspNetCore.Identity;

namespace BicoAuthService.Entities.Identity
{
    public class Role : IdentityRole<Guid>
    {

    }

    public class UserRole : IdentityUserRole<Guid>
    {
        public UserRole() : base()
        { }
    }

    public class RoleClaim : IdentityRoleClaim<Guid>
    {
        public RoleClaim() : base()
        { }
    }

    public class UserClaim : IdentityUserClaim<Guid>
    {
        public UserClaim() : base()
        { }
    }
    public class UserLogin : IdentityUserLogin<Guid>
    {
        public UserLogin() : base()
        { }
    }

    public class UserToken : IdentityUserToken<Guid>
    {
    }
}
