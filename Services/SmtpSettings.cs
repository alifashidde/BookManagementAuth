namespace BookManagementAuth.Services
{
    public class SmtpSettings
    {
        public string Host { get; set; }        // host address of the SMTP server 
        public int Port { get; set; }          // port number used for the SMTP connection 
        public string Username { get; set; }  // The username for authenticating with the SMTP server 
        public string Password { get; set; } // The password for authenticating with the SMTP server.
        public bool EnableSsl { get; set; } // Indicates whether SSL should be enabled for the SMTP connection.
    }
}
