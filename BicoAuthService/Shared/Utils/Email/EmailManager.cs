using Hangfire;
using SendGrid;
using SendGrid.Helpers.Mail;
using System.Net.Mail;

namespace BicoAuthService.Shared.Utils.Email
{
    public class EmailManager : IEmailManager
    {
        private readonly SendGridClient _clientKey;
        private readonly IConfiguration _config;
        private readonly EmailAddress _from;

        public EmailManager(IConfiguration configuration)
        {
            _config = configuration;
            var sendGridKey = configuration["Sendgrid:ApiKey"];
            var senderEmail = configuration["Sendgrid:SenderEmail"];

            _clientKey = new SendGridClient(sendGridKey);
            _from = new EmailAddress(senderEmail);
        }


        public void SendBulkEmail(string[] receiverAddress, string message, string subject)
        {
            BackgroundJob.Enqueue(() => SendBulkMail(receiverAddress, message, subject));
        }

        public void SendSingleEmail(string receiverAddress, string message, string subject)
        {
            BackgroundJob.Enqueue(() => SendSingleMail(receiverAddress, message, subject));
        }

        public async Task SendSingleMail(string receiverAddress, string message, string subject)
        {
            var To = new EmailAddress(receiverAddress);
            var plainText = message;
            var htmlContent = message;

            var msg = MailHelper.CreateSingleEmail(_from, To, subject, plainText, htmlContent);
            var response = await _clientKey.SendEmailAsync(msg);

            //Throw an exception if the response is not successful, so that hangfire can retry
            if (!response.IsSuccessStatusCode)
                throw new Exception(response.StatusCode.ToString());

        }

        public async Task SendBulkMail(string[] receiverAddress, string message, string subject)
        {
            var Tos = new List<EmailAddress>();

            foreach (var item in receiverAddress)
                Tos.Add(new EmailAddress(item));

            var plainText = "";
            var htmlContent = @$"
                <html><body><p>{message}</p></body></html>
            ";

            var msg = MailHelper.CreateSingleEmailToMultipleRecipients(_from, Tos, subject, plainText, htmlContent);
            var response = await _clientKey.SendEmailAsync(msg);

            //Throw an exception if the response is not successful, so that hangfire can retry
            if (!response.IsSuccessStatusCode)
                throw new Exception(response.StatusCode.ToString());
        }

        public string GetResetPasswordEmailTemplate(string emailLink, string email)
        {
            string body;
            var folderName = Path.Combine("wwwroot", "Templates", "ResetPassword.html");
            var filepath = Path.Combine(Directory.GetCurrentDirectory(), folderName);
            if (File.Exists(filepath))
                body = File.ReadAllText(filepath);
            else
                return null;

            string msgBody = body.Replace("{email_link}", emailLink).
                Replace("{email}", email);

            return msgBody;
        }

        public string GetOtpEmailTemplate(string otp)
        {
            string body;
            var folderName = Path.Combine("wwwroot", "Templates", "OtpTemplate.html");
            var filepath = Path.Combine(Directory.GetCurrentDirectory(), folderName);
            if (File.Exists(filepath))
                body = File.ReadAllText(filepath);
            else
                return null;

            string msgBody = body.Replace("{{_opt}}", otp);

            return msgBody;
        }
    }
}
