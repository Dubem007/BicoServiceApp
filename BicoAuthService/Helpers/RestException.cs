using System.Net;

namespace BicoAuthService.Helpers
{
    public class RestException : Exception
    {
        public string ErrorMessage { get; set; }
        public HttpStatusCode Code { get; }
        public object Errors { get; }

        public RestException(HttpStatusCode code, string message, object errors = null)
        {
            ErrorMessage = message;
            Code = code;
            Errors = errors;
        }
    }
}
