using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using BookManagementAuth.Models;
using BookManagementAuth.ViewModels;
using BookManagementAuth.Services;
using System.Text.Encodings.Web; // For HtmlEncoder
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace BookManagementAuth.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<AccountController> _logger;
        private readonly IEmailSender _emailSender;
        private readonly IConfiguration _configuration;

        public AccountController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ILogger<AccountController> logger,
            IEmailSender emailSender,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _emailSender = emailSender;
            _configuration = configuration;
        }

        // GET: /Account/Register
        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        private void SetJwtCookie(HttpContext httpContext, string jwtToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTimeOffset.UtcNow.AddDays(7)
            };

            httpContext.Response.Cookies.Append("jwt", jwtToken, cookieOptions);
        }

        public IActionResult AdminDashboard()
        {
            return View();
        }

        public async Task<IActionResult> ManageUsers()
        {
            // Get all users from the user manager
            var users = _userManager.Users.ToList();

            // Create a list to hold the users with their roles
            var usersWithRoles = new List<UserWithRolesViewModel>();

            // Iterate through users and get their roles
            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user); // Get roles for each user
                usersWithRoles.Add(new UserWithRolesViewModel
                {
                    User = user,
                    Roles = roles
                });
            }

            // Prepare the model with the users and their roles
            var model = new ManageUsersViewModel
            {
                Users = usersWithRoles 
            };

            return View(model);
        }

        [HttpGet]
        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(CreateUserViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser
                {
                    Email = model.Email,
                    UserName = model.Email // Use email as the username for consistency
                };

                var result = await _userManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    // Generate the email confirmation token
                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                    // Generate the callback URL for email confirmation
                    var callbackUrl = Url.Action(
                        "ConfirmEmail", // Action to confirm the email
                        "Account", // Controller
                        new { userId = user.Id, code = code }, // Pass userId and token
                        protocol: Request.Scheme); // Get the current protocol (http/https)

                    // Send the confirmation email with the link
                    await _emailSender.SendEmailAsync(
                        model.Email, // Recipient email
                        "Confirm Your Email Address", // Subject
                        $"Your account has been successfully created for you. Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

                    // Optionally, sign in the user after registration (if needed)
                    // await _signInManager.SignInAsync(user, isPersistent: false);

                    // Redirect to a registration confirmation page
                    return RedirectToAction("CreateUserConfirmation", new { email = model.Email });
                }

                // If registration fails, add the errors to the ModelState
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            // Return the view with validation errors if the model is invalid
            return View(model);
        }


        [HttpGet]
        public async Task<IActionResult> Edit(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var user = await _userManager.FindByIdAsync(id);

            if (user == null)
            {
                return NotFound();
            }

            var model = new EditUserViewModel
            {
                Id = user.Id,
                Email = user.Email,
                UserName = user.UserName // Add this line to get the username for editing
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(EditUserViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByIdAsync(model.Id);

                if (user == null)
                {
                    return NotFound();
                }

                // Check if email is updated
                var originalEmail = user.Email;
                user.Email = model.Email;
                user.UserName = model.Email; // UserName is typically the same as Email

                var result = await _userManager.UpdateAsync(user);

                if (result.Succeeded)
                {
                    // Send email notification after user details are updated
                    var emailSubject = "Your Account Information Has Been Updated";
                    var emailBody = $"Dear {user.Email},<br/><br/>Your account details have been successfully updated. " +
                                     $"Your new email address is {user.Email}. If you did not request this change, please contact support immediately.";

                    // Send email only if the email address was changed
                    if (originalEmail != user.Email)
                    {
                        await _emailSender.SendEmailAsync(user.Email, emailSubject, emailBody);
                    }

                    _logger.LogInformation("User updated successfully.");
                    return RedirectToAction("ManageUsers");
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> DeleteConfirmation(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            var model = new DeleteConfirmationViewModel
            {
                UserId = user.Id,
                UserEmail = user.Email
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return NotFound();
            }

            var user = await _userManager.FindByIdAsync(id);

            if (user == null)
            {
                return NotFound();
            }

            var result = await _userManager.DeleteAsync(user);

            if (result.Succeeded)
            {
                // Send email notification after successful deletion
                var emailSubject = "Your Account Has Been Deleted";
                var emailBody = $"Dear {user.Email},<br/><br/>Your account has been successfully deleted. If you did not request this, please contact support immediately.";

                // Send the email using the email sender service
                await _emailSender.SendEmailAsync(user.Email, emailSubject, emailBody);

                // Log the deletion (optional)
                _logger.LogInformation($"User {user.Email} was deleted successfully.");

                // Redirect to the manage users page after successful deletion
                return RedirectToAction("ManageUsers");
            }

            // If deletion failed, return errors
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View();
        }

        // POST: /Account/Register
        [HttpPost] // Handles HTTP POST requests.
        [ValidateAntiForgeryToken] // Protects against CSRF attacks.
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid) // Validate user input.
            {
                var user = new ApplicationUser
                {
                    UserName = model.Email, // Use email as username.
                    Email = model.Email     // Assign email address.
                };

                var result = await _userManager.CreateAsync(user, model.Password); // Create user.

                if (result.Succeeded) // If user creation succeeds.
                {
                    // Generate email confirmation token
                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                    // Construct the confirmation URL
                    var callbackUrl = Url.Action(
                        "ConfirmEmail", "Account",
                        new { userId = user.Id, code = code }, protocol: Request.Scheme);

                    // Send the confirmation email
                    await _emailSender.SendEmailAsync(
                        model.Email, "Confirm your email",
                        $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");


                    return RedirectToAction("RegistrationConfirmation", new { email = model.Email }); // Redirect to confirmation page.
                }

                foreach (var error in result.Errors) // Handle errors.
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            return View(model); // Return view if validation or creation fails.
        }

        // GET: /Account/RegistrationConfirmation
        [HttpGet]
        public IActionResult RegistrationConfirmation(string email)
        {
            return View(new RegistrationConfirmationViewModel { Email = email });
        }

        // GET: /Account/RegistrationConfirmation
        [HttpGet]
        public IActionResult CreateUserConfirmation(string email)
        {
            return View(new CreateUserConfirmation { Email = email });
        }

        // GET: /Account/Login
        [HttpGet]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            var model = new LoginViewModel();
            return View(model);
        }
        // Handles HTTP GET requests for verifying authenticator code.
        [HttpGet]
        public IActionResult VerifyAuthenticatorCode(string provider, string userId)
        {
            // Return 400 if parameters are invalid.
            if (string.IsNullOrEmpty(provider) || string.IsNullOrEmpty(userId))
            {
                return BadRequest("Provider and UserId cannot be null or empty");
            }

            // Create and pass model to the view.
            var model = new VerifyAuthenticatorCodeViewModel
            {
                Provider = provider,
                UserId = userId
            };

            return View(model); // Render view with the model.
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyAuthenticatorCode(VerifyAuthenticatorCodeViewModel model)
        {
            // Validate model
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // Find user by ID
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "User not found.");
                return View(model);
            }

            // Verify 2FA token
            var is2faTokenValid = await _userManager.VerifyTwoFactorTokenAsync(user, model.Provider, model.Code);
            if (is2faTokenValid)
            {
                // Sign in user
                await _signInManager.SignInAsync(user, isPersistent: model.RememberMe);

                // Generate and set JWT token
                var jwtToken = GenerateJwtToken(user);
                SetJwtCookie(HttpContext, jwtToken);

                // Check user role and redirect
                var roles = await _userManager.GetRolesAsync(user);
                if (roles.Contains("Admin"))
                {
                    return Redirect($"https://localhost:7018/Home/Index?token={jwtToken}");
                }
                else
                {
                    return Redirect($"https://localhost:7018/book/booklist?token={jwtToken}");
                }
            }
            else
            {
                // Handle invalid MFA code
                ModelState.AddModelError(string.Empty, "Invalid MFA code.");
                return View(model);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            if (!ModelState.IsValid) // Validate input fields.
            {
                return View(model); // Return view if input validation fails.
            }

            // Find user by email.
            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user == null) // User does not exist.
            {
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return View(model);
            }

            if (!await _userManager.IsEmailConfirmedAsync(user)) // check if Email not confirmed.
            {
                ModelState.AddModelError(string.Empty, "Please confirm your email before logging in.");
                return View(model);
            }

            if (await _userManager.GetTwoFactorEnabledAsync(user)) // Check if MFA is enabled.
            {
                var passwordCheck = await _signInManager.CheckPasswordSignInAsync(user, model.Password, lockoutOnFailure: true);

                if (passwordCheck.Succeeded)
                {
                    var code = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);

                    await _emailSender.SendEmailAsync(
                        user.Email,
                        "Your MFA Code",
                        $"Your multi-factor authentication code is: {code}.");

                    return RedirectToAction("VerifyAuthenticatorCode", new { provider = "Email", userId = user.Id });
                }

                if (passwordCheck.IsLockedOut) // Account locked due to failed attempts.
                {
                    return RedirectToAction("Lockout");
                }

                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return View(model);
            }

            // Process login without MFA.
            var signInResult = await _signInManager.PasswordSignInAsync(user, model.Password, model.RememberMe, lockoutOnFailure: true);

            if (signInResult.Succeeded)
            {
                return RedirectToLocal(returnUrl); // Redirect to specified return URL or default page.
            }

            if (signInResult.IsLockedOut) // Handle account lockout.
            {
                return RedirectToAction("Lockout");
            }

            // Invalid login attempt.
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return View(model);
        }

        private IActionResult RedirectToLocal(string returnUrl)
        {
            return Url.IsLocalUrl(returnUrl) ? Redirect(returnUrl) : RedirectToAction("Index", "Home");
        }

        private string GenerateJwtToken(ApplicationUser user)
        {
            // Get user roles.
            var roles = _userManager.GetRolesAsync(user).Result;

            // Create token handler.
            var tokenHandler = new JwtSecurityTokenHandler();

            // Get secret key from config.
            var key = Encoding.UTF8.GetBytes(_configuration["JwtSettings:SecretKey"]);

            // Define token details.
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                // Add user claims.
                Subject = new ClaimsIdentity(new[]
                {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id), // User ID.
            new Claim(JwtRegisteredClaimNames.Email, user.Email), // User email.
            new Claim(ClaimTypes.Role, "Admin"), // Hardcoded admin role.
            new Claim(ClaimTypes.Role, roles.FirstOrDefault() ?? "User") // Dynamic user role.
        }),
                Expires = DateTime.UtcNow.AddHours(1), // Token expiry.
                Issuer = _configuration["JwtSettings:Issuer"], // Token issuer.
                Audience = _configuration["JwtSettings:Audience"], // Token audience.
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature) // Signing key and algorithm.
            };

            // Generate and return token.
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }


        [HttpGet]
        public IActionResult Lockout()
        {
            return View(new LockoutViewModel());
        }

        [HttpGet]
        // GET: /Account/ManageMFA
        [HttpGet]
        public async Task<IActionResult> ManageMFA()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToAction("Login");
            }

            var model = new ManageMFAViewModel
            {
                IsMfaEnabled = await _userManager.GetTwoFactorEnabledAsync(user)
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EnableMFA()
        {
            // Retrieve the current user
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                // Redirect to login page if user is not found
                return RedirectToAction("Login", "Account");
            }

            // Check if MFA is already enabled
            if (await _userManager.GetTwoFactorEnabledAsync(user))
            {
                TempData["SuccessMessage"] = "Multi-Factor Authentication is already enabled.";
                return RedirectToAction("Login", "Account");
            }

            // Enable MFA logic here
            var tokenProvider = TokenOptions.DefaultEmailProvider;
            var token = await _userManager.GenerateTwoFactorTokenAsync(user, tokenProvider);

            // Optional: Send an email or notify user about enabling MFA
            await _emailSender.SendEmailAsync(
                user.Email,
                "Multi-Factor Authentication Enabled",
                "You have successfully enabled Multi-Factor Authentication (MFA)."
            );

            // Enable MFA for the user
            var result = await _userManager.SetTwoFactorEnabledAsync(user, true);
            if (!result.Succeeded)
            {
                ModelState.AddModelError(string.Empty, "An error occurred while enabling MFA. Please try again.");
                return View();
            }

            _logger.LogInformation($"User {user.Email} has enabled MFA.");

            // Set success message and redirect to login
            TempData["SuccessMessage"] = "Multi-Factor Authentication enabled successfully. Please log in again.";
            return RedirectToAction("Login", "Account");
        }

        // POST: /Account/ResendMfaCode
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResendMfaCode(string returnUrl = null, bool rememberMe = false)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                return RedirectToAction("Login");
            }

            var code = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
            await _emailSender.SendEmailAsync(
                user.Email,
                "Your MFA Code",
                $"Your new multi-factor authentication code is: <b>{code}</b>. Please enter this code to complete your login.");

            TempData["MfaResendSuccess"] = "A new MFA code has been sent to your email.";
            return RedirectToAction("VerifyAuthenticatorCode", new { returnUrl, rememberMe });
        }

        // GET: /Account/ForgotPassword
        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        // POST: /Account/ForgotPassword
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
                {
                    // Do not reveal that the user does not exist or is not confirmed
                    return RedirectToAction("ForgotPasswordConfirmation");
                }

                // Generate password reset token
                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callbackUrl = Url.Action(
                    "ResetPassword",
                    "Account",
                    new { code = code, email = model.Email },
                    protocol: Request.Scheme);

                await _emailSender.SendEmailAsync(
                    model.Email,
                    "Reset your password",
                    $"Please reset your password by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

                return RedirectToAction("ForgotPasswordConfirmation");
            }

            return View(model);
        }

        // GET: /Account/ForgotPasswordConfirmation
        [HttpGet]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        // GET: /Account/ResetPassword
        [HttpGet]
        public IActionResult ResetPassword(string code = null, string email = null)
        {
            if (code == null || email == null)
            {
                return RedirectToAction("Index", "Home");
            }

            var model = new ResetPasswordViewModel { Code = code, Email = email };
            return View(model);
        }

        // POST: /Account/ResetPassword
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            // Validate form input
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // Find user by email
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return RedirectToAction("ResetPasswordConfirmation"); // Redirect if user not found
            }

            // Attempt to reset password
            var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction("ResetPasswordConfirmation"); // Redirect on success
            }

            // Add error messages
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            // Return view with errors
            return View(model);
        }


        // GET: /Account/ResetPasswordConfirmation
        [HttpGet]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        // POST: /Account/Logout
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            _logger.LogInformation("User logged out.");
            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            // Validate inputs
            if (userId == null || code == null)
            {
                return RedirectToAction("Index", "Home"); // Redirect if invalid
            }

            // Find the user by ID
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return RedirectToAction("Index", "Home"); // Redirect if user not found
            }

            // Confirm the user's email
            var result = await _userManager.ConfirmEmailAsync(user, code);
            if (result.Succeeded)
            {
                return View("ConfirmEmail"); // Show confirmation view
            }
            else
            {
                return View("Error"); // Show error view
            }
        }


    }
}
