using System.Net;
using System.Net.Mail;

namespace UserManagement.Services
{
    public class SmtpEmailService : IEmailService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<SmtpEmailService> _logger;

        public SmtpEmailService(IConfiguration configuration, ILogger<SmtpEmailService> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        public async Task SendEmailAsync(string toEmail, string subject, string htmlBody)
        {
            var smtpHost = _configuration["Email:SmtpHost"] ?? "smtp.gmail.com";
            var smtpPort = _configuration.GetValue<int>("Email:SmtpPort", 587);
            var smtpUser = _configuration["Email:SmtpUser"];
            var smtpPass = _configuration["Email:SmtpPass"];
            var fromEmail = _configuration["Email:FromEmail"] ?? smtpUser;
            var fromName = _configuration["Email:FromName"] ?? "UserManagement";

            if (string.IsNullOrWhiteSpace(smtpUser) || string.IsNullOrWhiteSpace(smtpPass))
            {
                _logger.LogWarning("SMTP credentials not configured. Email not sent to {Email}. Subject: {Subject}", toEmail, subject);
                _logger.LogInformation("Email body that would have been sent:\n{Body}", htmlBody);
                return;
            }

            using var client = new SmtpClient(smtpHost, smtpPort)
            {
                Credentials = new NetworkCredential(smtpUser, smtpPass),
                EnableSsl = true
            };

            var message = new MailMessage
            {
                From = new MailAddress(fromEmail!, fromName),
                Subject = subject,
                Body = htmlBody,
                IsBodyHtml = true
            };
            message.To.Add(toEmail);

            await client.SendMailAsync(message);
            _logger.LogInformation("Email sent to {Email} with subject: {Subject}", toEmail, subject);
        }
    }
}
