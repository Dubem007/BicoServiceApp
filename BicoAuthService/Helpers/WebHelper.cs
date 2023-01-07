namespace BicoAuthService.Helpers
{
    public interface IWebHelper
    {
        UserHelperDto User();
    }

    public class WebHelper : IWebHelper
    {
        private static IHttpContextAccessor _httpContextAccessor;
        public static void Configure(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        public static HttpContext HttpContextMapp
        {
            get { return _httpContextAccessor.HttpContext; }
        }

        private static UserHelperDto UserHelper
        {
            get
            {
                var userId = _httpContextAccessor?.HttpContext?.User.Claims.Where(x => x.Type == ClaimTypeHelper.UserId).FirstOrDefault()?.Value ?? "";
                Guid.TryParse(userId, out Guid id);
                var email = _httpContextAccessor?.HttpContext?.User?.Claims?.Where(x => x.Type == ClaimTypeHelper.Email).FirstOrDefault()?.Value ?? "";

                var result = new UserHelperDto
                {
                    UserId = id,
                    Email = email
                };
                return result;
            }
        }

        public UserHelperDto User()
        {
            return UserHelper;
        }
    }

    public class UserHelperDto
    {
        public Guid UserId { get; set; }
        public string Email { get; set; }
    }
}
