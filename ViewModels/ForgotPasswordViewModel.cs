using System.ComponentModel.DataAnnotations;

namespace BookManagementAuth.ViewModels
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
