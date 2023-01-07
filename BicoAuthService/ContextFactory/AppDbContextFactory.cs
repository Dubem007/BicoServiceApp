using Microsoft.EntityFrameworkCore.Design;
using Microsoft.EntityFrameworkCore;
using BicoAuthService.Data.DbContext;

namespace BicoAuthService.Data.ContextFactory
{
    public class AppDbContextFactory : IDesignTimeDbContextFactory<AppDbContext>
    {
        public AppDbContext CreateDbContext(string[] args)
        {
            var config = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json")
                .AddJsonFile("appsettings.Development.json", reloadOnChange: true, optional: true)
                .AddEnvironmentVariables()
                .Build();

            var builder = new DbContextOptionsBuilder<AppDbContext>()
                .UseSqlServer(config.GetConnectionString("DefaultConnection"),
                    b => b.MigrationsAssembly("BicoAuthService"));
            return new AppDbContext(builder.Options);
        }
    }
}
