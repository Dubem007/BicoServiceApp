using BicoAuthService.Data.DbContext;
using BicoAuthService.Entities.Identity;
using Microsoft.EntityFrameworkCore;

namespace BicoAuthService.Data
{
    public static class PrepDB
    {
        public static void prepopulation(IApplicationBuilder app)
        {
            using (var serviceScope = app.ApplicationServices.CreateScope()) 
            {
                seedData(serviceScope.ServiceProvider.GetService<AppDbContext>());
            }

        }

        public static void seedData(AppDbContext context) 
        {
            System.Console.WriteLine("Applying Migrations.........");

            context.Database.Migrate();

            if (!context.Roles.Any()) {

                System.Console.WriteLine("Adding data....seeding..");

                context.Roles.AddRange(
                     new Role()
                     {
                         Name = "Regular",
                         NormalizedName = "Regular".ToUpper(),
                         ConcurrencyStamp = Guid.NewGuid().ToString(),
                     },
                    new Role()
                    {
                        Name = "Admin",
                        NormalizedName = "Admin".ToUpper(),
                        ConcurrencyStamp = Guid.NewGuid().ToString(),
                    },
                    new Role()
                    {
                        Name = "Manager",
                        NormalizedName = "Manager".ToUpper(),
                        ConcurrencyStamp = Guid.NewGuid().ToString(),
                    }
                    );
                context.SaveChanges();


            }
            else {
                System.Console.WriteLine("Already have data....no seeding..");
            }
        
        }
    }
}
