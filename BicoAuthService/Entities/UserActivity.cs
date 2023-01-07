using BicoAuthService.Entities.Identity;

namespace BicoAuthService.Entities
{
    public class UserActivity : AuditableEntity
    {
        public Guid Id { get; set; }
        public string EventType { get; set; }
        public string ObjectClass { get; set; }
        public Guid ObjectId { get; set; }
        public string Details { get; set; }
        public Guid UserId { get; set; }
        public User User { get; set; }
    }
}
