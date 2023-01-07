using BicoAuthService.Entities.Identity;

namespace BicoAuthService.Data.DbSeeds
{
    public static class SeedData
    {
        public static List<Role> GetRoles()
        {
            return new List<Role>
            {
                new Role
                {
                    Name = "Regular",
                    NormalizedName = "Regular".ToUpper(),
                    ConcurrencyStamp = Guid.NewGuid().ToString(),
                },
                new Role
                {
                    Name = "Admin",
                    NormalizedName = "Admin".ToUpper(),
                    ConcurrencyStamp = Guid.NewGuid().ToString(),
                },
                new Role
                {
                    Name = "Manager",
                    NormalizedName = "Manager".ToUpper(),
                    ConcurrencyStamp = Guid.NewGuid().ToString(),
                }
            };
        }
    }
}
