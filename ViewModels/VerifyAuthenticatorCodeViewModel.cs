namespace BookManagementAuth.Models
{
    public class VerifyAuthenticatorCodeViewModel
    {
        public string Code { get; set; }
        public string Provider { get; set; }
        public bool RememberMe { get; set; }
        public bool RememberMachine { get; set; }
        public string UserId { get; set; } 
    }

}
