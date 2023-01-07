namespace BicoAuthService.Shared.Utils.Email
{
    public interface IEmailManager
    {
        void SendSingleEmail(string receiverAddress, string message, string subject);
        void SendBulkEmail(string[] receiverAddress, string message, string subject);
        Task SendSingleMail(string receiverAddress, string message, string subject);
        string GetResetPasswordEmailTemplate(string emailLink, string email);
        string GetOtpEmailTemplate(string otp);
    }
}
