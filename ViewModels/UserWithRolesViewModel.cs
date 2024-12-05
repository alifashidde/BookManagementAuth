using BookManagementAuth.Models;

namespace BookManagementAuth.ViewModels
{
    public class UserWithRolesViewModel
    {
        public ApplicationUser User { get; set; }
        public IList<string> Roles { get; set; }
        public string UserName => User.UserName;
    }

}
