using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace BookManagementAuth.Services
{
    // The EmailSender class implements the IEmailSender interface and provides functionality to send emails asynchronously.
    public class EmailSender : IEmailSender
    {
        private readonly SmtpSettings _smtpSettings; // Stores SMTP configuration settings.
        private readonly ILogger<EmailSender> _logger; // Used for logging errors and events.

        // Constructor injects the SMTP settings and logger dependencies.
        public EmailSender(IOptions<SmtpSettings> smtpSettings, ILogger<EmailSender> logger)
        {
            _smtpSettings = smtpSettings.Value; // Retrieves the SMTP settings from configuration.
            _logger = logger; // Initializes the logger.
        }

        // Method to send an email asynchronously.
        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            try
            {
                // Creates a new SMTP client with the specified settings.
                using var smtpClient = new SmtpClient(_smtpSettings.Host, _smtpSettings.Port)
                {
                    // Configures credentials and SSL settings for secure email transmission.
                    Credentials = new NetworkCredential(_smtpSettings.Username, _smtpSettings.Password),
                    EnableSsl = _smtpSettings.EnableSsl,
                };

                // Creates a MailMessage object to hold the email details.
                var mailMessage = new MailMessage
                {
                    From = new MailAddress(_smtpSettings.Username), // Sets the sender's email address.
                    Subject = subject, // Sets the subject of the email.
                    Body = htmlMessage, // Sets the body content of the email.
                    IsBodyHtml = true, // Specifies that the body content is HTML.
                };

                // Adds the recipient email address.
                mailMessage.To.Add(email);

                // Asynchronously sends the email.
                await smtpClient.SendMailAsync(mailMessage);
            }
            catch (SmtpException smtpEx)
            {
                // Logs an error if an SMTP-specific issue occurs during the email sending process.
                _logger.LogError(smtpEx, "SMTP error occurred while sending email.");
                throw;
            }
            catch (Exception ex)
            {
                // Logs any other generic exceptions and rethrows them.
                _logger.LogError(ex, "An error occurred while sending email.");
                throw;
            }
        }
    }
}
