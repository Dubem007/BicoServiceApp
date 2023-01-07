using BicoAuthService.Data.DbContext;

namespace BicoAuthService.Data.DbSeeds
{
    public static class DbInitializer
    {
        public static async Task SeedRoleData(this IHost host)
        {
            var serviceProvider = host.Services.CreateScope().ServiceProvider;
            var context = serviceProvider.GetRequiredService<AppDbContext>();
            var roles = SeedData.GetRoles();

            if (!context.Roles.Any())
            {
                await context.Roles.AddRangeAsync(roles);
                await context.SaveChangesAsync();
            }
        }

    }
}

