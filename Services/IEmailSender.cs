namespace BookManagementAuth.Services
{
    // Defines an interface for sending emails asynchronously.
    public interface IEmailSender
    {
        // Asynchronously sends an email with the specified recipient, subject, and HTML content.
        Task SendEmailAsync(string email, string subject, string htmlMessage);
    }
}





