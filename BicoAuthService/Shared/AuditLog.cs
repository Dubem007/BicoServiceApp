using BicoAuthService.Entities;

namespace BicoAuthService.Shared
{
    public class AuditLog
    {
        public static UserActivity UserActivity(object eventType, Guid userId, string objectClass, string details, Guid objectId)
        {
            return new UserActivity
            {
                EventType = eventType.GetType().Name,
                UserId = userId,
                ObjectClass = objectClass,
                Details = details,
                ObjectId = objectId
            };
        }
    }
}
