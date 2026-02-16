using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using UserManagement.Data;
using UserManagement.DTOs.Auth;
using UserManagement.DTOs.Common;
using UserManagement.DTOs.Profile;
using UserManagement.Services;

namespace UserManagement.Controllers
{
    // This controller handles all user-related operations such as registration, login, profile management, password reset, and email confirmation.
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]

    public class UserManagementController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;
        private readonly string _jwtKey;
        private readonly string? _jwtIssuer;
        private readonly string? _jwtAudience;
        private readonly int _jwtExpiry;
        private readonly int _refreshTokenExpiryDays;
        private readonly IConfiguration _configuration;

        public UserManagementController(UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            RoleManager<IdentityRole> roleManager,
            IEmailService emailService,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _configuration = configuration;
            _jwtKey = configuration["Jwt:Key"] ?? throw new ArgumentException("Jwt:Key is missing");
            _jwtIssuer = configuration["Jwt:Issuer"];
            _jwtAudience = configuration["Jwt:Audience"];
            var expiryValue = configuration["Jwt:ExpiryInMinutes"];
            if (string.IsNullOrWhiteSpace(expiryValue))
            {
                throw new ArgumentException("Jwt:ExpiryInMinutes configuration value is missing or empty.");
            }
            _jwtExpiry = int.Parse(expiryValue);
            _refreshTokenExpiryDays = configuration.GetValue<int>("Jwt:RefreshTokenExpiryDays", 7);
        }

        private string? GetCurrentUserId()
        {
            return User.FindFirstValue(JwtRegisteredClaimNames.Sub)
                   ?? User.FindFirstValue(ClaimTypes.NameIdentifier);
        }


        // POST: api/UserManagement/register
        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequestDto model)
        {
            if (!ModelState.IsValid)
            {
                var errors = ModelState.Values
                    .SelectMany(v => v.Errors)
                    .Select(e => e.ErrorMessage)
                    .ToList();

                return BadRequest(new ApiResponse<object>
                {
                    success = false,
                    message = "Validation failed",
                    errors = errors
                });
            }

            var existingUser = await _userManager.FindByEmailAsync(model.Email);
            if (existingUser != null)
            {
                return Conflict(new ApiResponse<object>
                {
                    success = false,
                    message = "Validation failed",
                    errors = new List<string> { "Email already exists" }
                });
            }

            if (model.Password != model.ConfirmPassword)
            {
                return BadRequest(new ApiResponse<object>
                {
                    success = false,
                    message = "Validation failed",
                    errors = new List<string> { "Passwords do not match" }
                });
            }

            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email,
                Name = model.Name
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, "User");

                // Generate email confirmation token and send verification email
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var encodedToken = Uri.EscapeDataString(token);
                var appUrl = _configuration["AppUrl"] ?? "https://localhost:7122";
                var confirmationLink = $"{appUrl}/api/UserManagement/confirm-email?userId={user.Id}&token={encodedToken}";

                await _emailService.SendEmailAsync(
                    user.Email!,
                    "Confirm your email",
                    $"<h2>Welcome {user.Name}!</h2>" +
                    $"<p>Please confirm your email by clicking the link below:</p>" +
                    $"<a href=\"{confirmationLink}\">Confirm Email</a>"
                );

                return Ok(new ApiResponse<object>
                {
                    success = true,
                    message = "User registered successfully. Please check your email to confirm your account."
                });
            }

            return UnprocessableEntity(new ApiResponse<object>
            {
                success = false,
                message = "User registration failed",
                errors = result.Errors.Select(e => e.Description).ToList()
            });
        }


        // GET: api/UserManagement/confirm-email
        [AllowAnonymous]
        [HttpGet("confirm-email")]
        [ApiExplorerSettings(IgnoreApi = true)]
        public async Task<IActionResult> ConfirmEmail([FromQuery] string userId, [FromQuery] string token)
        {
            string title;
            string message;
            bool isSuccess;

            if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(token))
            {
                title = "Invalid Link";
                message = "The confirmation link is invalid. Please request a new confirmation email.";
                isSuccess = false;
            }
            else
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                {
                    title = "User Not Found";
                    message = "We could not find your account. Please register again.";
                    isSuccess = false;
                }
                else if (user.EmailConfirmed)
                {
                    title = "Already Confirmed";
                    message = "Your email is already confirmed. You can log in to your account.";
                    isSuccess = true;
                }
                else
                {
                    var result = await _userManager.ConfirmEmailAsync(user, token);
                    if (result.Succeeded)
                    {
                        title = "Email Confirmed!";
                        message = "Your email has been confirmed successfully. You can now log in to your account.";
                        isSuccess = true;
                    }
                    else
                    {
                        title = "Confirmation Failed";
                        message = "The confirmation link has expired or is invalid. Please request a new confirmation email.";
                        isSuccess = false;
                    }
                }
            }

            var html = $@"
<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 400px; margin: 60px auto; padding: 20px; }}
        h2 {{ color: #333; }}
        input {{ width: 100%; padding: 10px; margin: 8px 0; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }}
        button {{ width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }}
        button:hover {{ background: #0056b3; }}
        #message {{ margin-top: 16px; padding: 10px; border-radius: 4px; display: none; }}
        .success {{ background: #d4edda; color: #155724; display: block !important; }}
        .error {{ background: #f8d7da; color: #721c24; display: block !important; }}
    </style>
</head>
<body>
    <h2>{title}</h2>
    <div id='message' class='{(isSuccess ? "success" : "error")}'>{message}</div>
</body>
</html>";
            return Content(html, "text/html");
        }


        // POST: api/UserManagement/resend-confirmation
        [AllowAnonymous]
        [HttpPost("resend-confirmation")]
        public async Task<IActionResult> ResendConfirmation([FromBody] ResendConfirmationRequest model)
        {
            if (!ModelState.IsValid)
            {
                var errors = ModelState.Values
                    .SelectMany(v => v.Errors)
                    .Select(e => e.ErrorMessage)
                    .ToList();
                return BadRequest(new ApiResponse<object>
                {
                    success = false,
                    message = "Validation failed",
                    errors = errors
                });
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
             
            if (user == null || user.EmailConfirmed)
            {
                return Ok(new ApiResponse<object>
                {
                    success = true,
                    message = "If the email exists and is not confirmed, a confirmation link has been sent."
                });
            }

            // Invalidate any previously issued confirmation tokens
            await _userManager.UpdateSecurityStampAsync(user);

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var encodedToken = Uri.EscapeDataString(token);
            var appUrl = _configuration["AppUrl"] ?? "https://localhost:7122";
            var confirmationLink = $"{appUrl}/api/UserManagement/confirm-email?userId={user.Id}&token={encodedToken}";

            await _emailService.SendEmailAsync(
                user.Email!,
                "Confirm your email",
                $"<h2>Hello {user.Name}!</h2>" +
                $"<p>Please confirm your email by clicking the link below:</p>" +
                $"<a href=\"{confirmationLink}\">Confirm Email</a>"
            );
            
            return Ok(new ApiResponse<object>
            {
                success = true,
                message = "If the email exists and is not confirmed, a confirmation link has been sent."
            });
        }


        // POST: api/UserManagement/login
        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequestDto model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new ApiResponse<object>
                {
                    success = false,
                    message = "Validation failed"
                });
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return Unauthorized(new ApiResponse<object>
                {
                    success = false,
                    message = "Invalid email or password"
                });
            }

            if (!await _userManager.IsEmailConfirmedAsync(user))
            {
                return Unauthorized(new ApiResponse<object>
                {
                    success = false,
                    message = "Email is not confirmed. Please check your inbox or request a new confirmation email"
                });
            }

            var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, lockoutOnFailure: false);
            if (!result.Succeeded)
            {
                return Unauthorized(new ApiResponse<object>
                {
                    success = false,
                    message = "Invalid email or password"
                });
            }

            // Generate JWT token
            var token = await GenerateJwtToken(user);

            // Generate refresh token
            var refreshToken = GenerateRefreshToken();
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(_refreshTokenExpiryDays);
            await _userManager.UpdateAsync(user);

            var userRoles = await _userManager.GetRolesAsync(user);

            return Ok(new ApiResponse<object>
            {
                success = true,
                message = "Login successful",
                data = new
                {
                    token,
                    refreshToken,
                    expiration = DateTime.UtcNow.AddMinutes(_jwtExpiry),
                    roles = userRoles
                }
            });
     }

        // POST: api/UserManagement/refresh-token
        [AllowAnonymous]
        [HttpPost("refresh-token")]
        [ApiExplorerSettings(IgnoreApi = true)]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new ApiResponse<object>
                {
                    success = false,
                    message = "Validation failed"
                });
            }

            var user = await _userManager.Users
                .FirstOrDefaultAsync(u => u.RefreshToken == model.Token);

            if (user == null || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            {
                return Unauthorized(new ApiResponse<object>
                {
                    success = false,
                    message = "Invalid or expired refresh token"
                });
            }

            var newAccessToken = await GenerateJwtToken(user);
            var newRefreshToken = GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(_refreshTokenExpiryDays);
            await _userManager.UpdateAsync(user);

            return Ok(new ApiResponse<object>
            {
                success = true,
                message = "Token refreshed successfully",
                data = new
                {
                    token = newAccessToken,
                    refreshToken = newRefreshToken,
                    expiration = DateTime.UtcNow.AddMinutes(_jwtExpiry)
                }
            });
        }


        // POST: api/UserManagement/logout
        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            var userId = GetCurrentUserId();
            if (userId != null)
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user != null)
                {
                    user.RefreshToken = null;
                    user.RefreshTokenExpiryTime = null;
                    await _userManager.UpdateAsync(user);
                }
            }

            await _signInManager.SignOutAsync();

            return Ok(new ApiResponse<object>
            {
                success = true,
                message = "User logged out successfully"
            });
        }


        // POST: api/UserManagement/forgot-password
        [AllowAnonymous]
        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest model)
        {
            if (!ModelState.IsValid)
            {
                var errors = ModelState.Values
                    .SelectMany(v => v.Errors)
                    .Select(e => e.ErrorMessage)
                    .ToList();
                return BadRequest(new ApiResponse<object>
                {
                    success = false,
                    message = "Validation failed",
                    errors = errors
                });
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            // Always return success to prevent email enumeration
            if (user == null || !await _userManager.IsEmailConfirmedAsync(user))
            {
                return Ok(new ApiResponse<object>
                {
                    success = true,
                    message = "If the email is registered, a password reset link has been sent."
                });
            }

            // Invalidate any previously issued password reset tokens
            await _userManager.UpdateSecurityStampAsync(user);

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = Uri.EscapeDataString(token);
            var appUrl = _configuration["AppUrl"] ?? "https://localhost:7122";
            var resetLink = $"{appUrl}/api/UserManagement/reset-password?email={Uri.EscapeDataString(user.Email!)}&token={encodedToken}";

            await _emailService.SendEmailAsync(
                user.Email!,
                "Reset your password",
                $"<h2>Password Reset</h2>" +
                $"<p>You requested a password reset. Click the link below to set a new password:</p>" +
                $"<a href=\"{resetLink}\" style='display:inline-block;padding:10px 20px;background:#007bff;color:#fff;text-decoration:none;border-radius:5px;'>Reset Password</a>" +
                $"<p style='margin-top:16px;color:#666;'>If you did not request this, please ignore this email.</p>"
            );

            return Ok(new ApiResponse<object>
            {
                success = true,
                message = "If the email is registered, a password reset link has been sent."
            });
        }


        // GET: api/UserManagement/reset-password
        [AllowAnonymous]
        [HttpGet("reset-password")]
        [ApiExplorerSettings(IgnoreApi = true)]
        public IActionResult ResetPasswordForm([FromQuery] string email, [FromQuery] string token)
        {
            if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(token))
            {
                var errorHtml = @"
<!DOCTYPE html>
<html>
<head>
    <title>Invalid Link</title>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
    <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 60px auto; padding: 20px; }
        h2 { color: #333; }
        .error { background: #f8d7da; color: #721c24; padding: 10px; border-radius: 4px; }
    </style>
</head>
<body>
    <h2>Invalid Link</h2>
    <div class='error'>The password reset link is invalid or incomplete. Please request a new one.</div>
</body>
</html>";
                return Content(errorHtml, "text/html");
            }

            var appUrl = _configuration["AppUrl"] ?? "https://localhost:7122";
            var html = $@"
<!DOCTYPE html>
<html>
<head>
    <title>Reset Password</title>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 400px; margin: 60px auto; padding: 20px; }}
        h2 {{ color: #333; }}
        label {{ display: block; margin-top: 12px; font-weight: bold; }}
        input {{ width: 100%; padding: 10px; margin: 8px 0; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }}
        button {{ width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; margin-top: 16px; }}
        button:hover {{ background: #0056b3; }}
        #message {{ margin-top: 16px; padding: 10px; border-radius: 4px; display: none; }}
        .success {{ background: #d4edda; color: #155724; display: block !important; }}
        .error {{ background: #f8d7da; color: #721c24; display: block !important; }}
    </style>
</head>
<body>
    <h2>Reset Password</h2>
    <form id='resetForm'>
        <label for='newPassword'>New Password</label>
        <input type='password' id='newPassword' name='newPassword' required minlength='8' placeholder='Enter new password' />
        <label for='confirmPassword'>Confirm Password</label>
        <input type='password' id='confirmPassword' name='confirmPassword' required minlength='8' placeholder='Confirm new password' />
        <button type='submit'>Reset Password</button>
    </form>
    <div id='message'></div>
    <script>
        document.getElementById('resetForm').addEventListener('submit', async function(e) {{
            e.preventDefault();
            var msg = document.getElementById('message');
            var newPassword = document.getElementById('newPassword').value;
            var confirmPassword = document.getElementById('confirmPassword').value;
            if (newPassword !== confirmPassword) {{
                msg.className = 'error';
                msg.textContent = 'Passwords do not match.';
                return;
            }}
            msg.className = '';
            msg.style.display = 'none';
            try {{
                var resp = await fetch('{appUrl}/api/UserManagement/reset-password', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{
                        email: '{System.Web.HttpUtility.JavaScriptStringEncode(email)}',
                        token: '{System.Web.HttpUtility.JavaScriptStringEncode(token)}',
                        newPassword: newPassword
                    }})
                }});
                var data = await resp.json();
                if (data.success) {{
                    msg.className = 'success';
                    msg.textContent = data.message || 'Password reset successfully. You can now log in.';
                    document.getElementById('resetForm').style.display = 'none';
                }} else {{
                    msg.className = 'error';
                    msg.textContent = (data.errors && data.errors.join(', ')) || data.message || 'Password reset failed.';
                }}
            }} catch (err) {{
                msg.className = 'error';
                msg.textContent = 'An error occurred. Please try again.';
            }}
        }});
    </script>
</body>
</html>";
            return Content(html, "text/html");
        }


        // POST: api/UserManagement/reset-password
        [AllowAnonymous]
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest model)
        {
            if (!ModelState.IsValid)
            {
                var errors = ModelState.Values
                    .SelectMany(v => v.Errors)
                    .Select(e => e.ErrorMessage)
                    .ToList();
                return BadRequest(new ApiResponse<object>
                {
                    success = false,
                    message = "Validation failed",
                    errors = errors
                });
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return Ok(new ApiResponse<object>
                {
                    success = true,
                    message = "If the account exists, the password has been reset."
                });
            }

            var result = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);
            if (result.Succeeded)
            {
                user.RefreshToken = null;
                user.RefreshTokenExpiryTime = null;
                await _userManager.UpdateAsync(user);

                return Ok(new ApiResponse<object>
                {
                    success = true,
                    message = "Password has been reset successfully. You can now log in with your new password."
                });
            }

            return BadRequest(new ApiResponse<object>
            {
                success = false,
                message = "Password reset failed",
                errors = result.Errors.Select(e => e.Description).ToList()
            });
        }


        // GET: api/UserManagement/profile
        [HttpGet("profile")]
        public async Task<IActionResult> GetProfile()
        {
            var userId = GetCurrentUserId();
            if (userId == null)
            {
                return Unauthorized(new ApiResponse<object>
                {
                    success = false,
                    message = "User not authenticated"
                });
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    success = false,
                    message = "User not found"
                });
            }
            var userRoles = await _userManager.GetRolesAsync(user);
            return Ok(new ApiResponse<object>
            {
                success = true,
                message = "User profile retrieved successfully",
                data = new
                {
                    user.Id,
                    user.Name,
                    user.Email,
                    user.EmailConfirmed,
                    Roles = userRoles
                }
            });
        }


        // POST: api/UserManagement/change-password
        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest model)
        {
            // Validate request body and model state
            if (model == null)
            {
                return BadRequest(new ApiResponse<object>
                {
                    success = false,
                    message = "Validation failed",
                    errors = new List<string> { "Request body is required" }
                });
            }
            if (!ModelState.IsValid)
            {
                var errors = ModelState.Values
                    .SelectMany(v => v.Errors)
                    .Select(e => e.ErrorMessage)
                    .ToList();
                return BadRequest(new ApiResponse<object>
                {
                    success = false,
                    message = "Validation failed",
                    errors = errors
                });
            }
            var userId = GetCurrentUserId();
            if (userId == null)
            {
                return Unauthorized(new ApiResponse<object>
                {
                    success = false,
                    message = "User not authenticated",
                    errors = new List<string> { "Authorization token is missing or invalid" }
                });
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    success = false,
                    message = "User not found",
                    errors = new List<string> { "No user exists for the provided token" }
                });
            }
            var currentPasswordValid = await _userManager.CheckPasswordAsync(user, model.CurrentPassword);
            if (!currentPasswordValid)
            {
                return BadRequest(new ApiResponse<object>
                {
                    success = false,
                    message = "Validation failed",
                    errors = new List<string> { "Current password is incorrect" }
                });
            }
            if (model.CurrentPassword == model.NewPassword)
            {
                return BadRequest(new ApiResponse<object>
                {
                    success = false,
                    message = "Validation failed",
                    errors = new List<string> { "New password cannot be the same as the current password" }
                });
            }
            var passwordValidation = new List<string>();
            foreach (var validator in _userManager.PasswordValidators)
            {
                var validationResult = await validator.ValidateAsync(_userManager, user, model.NewPassword);
                if (!validationResult.Succeeded)
                {
                    passwordValidation.AddRange(validationResult.Errors.Select(e => e.Description));
                }
            }
            if (passwordValidation.Count > 0)
            {
                return BadRequest(new ApiResponse<object>
                {
                    success = false,
                    message = "Validation failed",
                    errors = passwordValidation.Distinct().ToList()
                });
            }
            var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
            if (result.Succeeded)
            {
                return Ok(new ApiResponse<object>
                {
                    success = true,
                    message = "Password changed successfully"
                });
            }
            return UnprocessableEntity(new ApiResponse<object>
            {
                success = false,
                message = "Password change failed",
                errors = result.Errors.Select(e => e.Description).ToList()
            });
        }


        // DELETE: api/UserManagement/delete-account
        [HttpDelete("delete-account")]
        public async Task<IActionResult> DeleteAccount()
        {
            var userId = GetCurrentUserId();
            if (userId == null)
            {
                return Unauthorized(new ApiResponse<object>
                {
                    success = false,
                    message = "User not authenticated"
                });
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    success = false,
                    message = "User not found"
                });
            }
            var result = await _userManager.DeleteAsync(user);
            if (result.Succeeded)
            {
                await _signInManager.SignOutAsync();
                return Ok(new ApiResponse<object>
                {
                    success = true,
                    message = "User account deleted successfully"
                });
            }
            return UnprocessableEntity(new ApiResponse<object>
            {
                success = false,
                message = "Account deletion failed",
                errors = result.Errors.Select(e => e.Description).ToList()
            });
        }


        // PUT: api/UserManagement/update-profile
        [HttpPut("update-profile")]
        public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileRequest model)
        {
            if (model == null)
            {
                return BadRequest(new ApiResponse<object>
                {
                    success = false,
                    message = "Validation failed",
                    errors = new List<string> { "Request body is required" }
                });
            }
            if (!ModelState.IsValid)
            {
                var errors = ModelState.Values
                    .SelectMany(v => v.Errors)
                    .Select(e => e.ErrorMessage)
                    .ToList();
                return BadRequest(new ApiResponse<object>
                {
                    success = false,
                    message = "Validation failed",
                    errors = errors
                });
            }
            var userId = GetCurrentUserId();
            if (userId == null)
            {
                return Unauthorized(new ApiResponse<object>
                {
                    success = false,
                    message = "User not authenticated"
                });
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    success = false,
                    message = "User not found"
                });
            }

            user.Name = model.Name ?? user.Name;

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                return UnprocessableEntity(new ApiResponse<object>
                {
                    success = false,
                    message = "Profile update failed",
                    errors = result.Errors.Select(e => e.Description).ToList()
                });
            }

            return Ok(new ApiResponse<object>
            {
                success = true,
                message = "User profile updated successfully"
            });
        }


        private static string GenerateRefreshToken()
        {
            var randomBytes = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);
            return Convert.ToBase64String(randomBytes);
        }

        private async Task<string> GenerateJwtToken(ApplicationUser user)
        {
            var key = _jwtKey;
            var issuer = _jwtIssuer ?? string.Empty;
            var audience = _jwtAudience ?? string.Empty;
            var expiry = _jwtExpiry;

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim("email", user.Email ?? string.Empty),
                new Claim("name", user.Name ?? string.Empty),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var roles = await _userManager.GetRolesAsync(user);
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(expiry),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}