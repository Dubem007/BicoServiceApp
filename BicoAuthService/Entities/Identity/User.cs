using Microsoft.AspNetCore.Identity;

namespace BicoAuthService.Entities.Identity
{
    public class User : IdentityUser<Guid>, IAuditableEntity
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string ImageUrl { get; set; }
        public string PrefferedName { get; set; }
        public string Email { get; set; }
        public DateTime DateOfBirth { get; set; }
        public string ProfessionalField { get; set; }
        public string? ProfileImage { get; set; }
        public string Location { get; set; }
        public string Bio { get; set; }
        public string Country { get; set; }
        public long RegStatus { get; set; }
        public bool IsActive { get; set; }
        public bool IsVerified { get; set; }
        public bool IsDeleted { get; set; }
        public DateTime? DeletedAt { get; set; }
        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiryTime { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
        public Guid? CreatedById { get; set; }
        public ICollection<UserActivity> UserActivities { get; set; }
        public string Status { get; set; }
        public DateTime? LastLogin { get; set; }
    }
}
