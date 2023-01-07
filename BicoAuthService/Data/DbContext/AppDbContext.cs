using BicoAuthService.Data.Configuration;
using BicoAuthService.Entities;
using BicoAuthService.Entities.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace BicoAuthService.Data.DbContext;

public class AppDbContext : IdentityDbContext<User, Role, Guid, UserClaim, UserRole, UserLogin, RoleClaim, UserToken>
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }

   


    public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        foreach (var item in ChangeTracker.Entries<AuditableEntity>())
        {
            switch (item.State)
            {
                case EntityState.Modified:
                    item.Entity.UpdatedAt = DateTime.UtcNow;
                    break;
                case EntityState.Added:
                    item.Entity.CreatedAt = DateTime.UtcNow;
                    break;
                default:
                    break;
            }
        }
        return await base.SaveChangesAsync(cancellationToken);
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.ApplyConfigurationsFromAssembly(typeof(UserConfiguration).Assembly);
    }

    public override DbSet<User> Users { get; set; }
    public DbSet<Token> Tokens { get; set; }
    public DbSet<UserActivity> UserActivities { get; set; }

}
