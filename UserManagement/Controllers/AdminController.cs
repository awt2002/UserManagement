using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.IdentityModel.Tokens.Jwt;
using UserManagement.Data;
using UserManagement.DTOs.Admin;
using UserManagement.DTOs.Common;
using UserManagement.Services;

namespace UserManagement.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Admin")]
    public class AdminController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration;

        public AdminController(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IEmailService emailService,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _configuration = configuration;
        }

        private string? GetCurrentUserId()
        {
            return User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value
                   ?? User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        }

        // GET: api/Admin/users search
        [HttpGet("users")]
        public async Task<IActionResult> GetAllUsers([FromQuery] string? search)
        {
            var query = _userManager.Users.AsQueryable();

            if (!string.IsNullOrWhiteSpace(search))
            {
                var term = search.ToLower();
                query = query.Where(u => u.Id.ToLower() == term || u.Name.ToLower().Contains(term) || (u.Email != null && u.Email.ToLower().Contains(term)));
            }

            var users = await query.OrderBy(u => u.Name).ToListAsync();

            var userList = new List<UserListItemDto>();
            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                userList.Add(new UserListItemDto
                {
                    Id = user.Id,
                    Name = user.Name,
                    Email = user.Email ?? string.Empty,
                    EmailConfirmed = user.EmailConfirmed,
                    IsLockedOut = await _userManager.IsLockedOutAsync(user),
                    Roles = roles.ToList()
                });
            }

            return Ok(new ApiResponse<List<UserListItemDto>>
            {
                success = true,
                message = "Users retrieved successfully",
                data = userList
            });
        }

        // DELETE: api/Admin/users/{id}
        [HttpDelete("users/{id}")]
        public async Task<IActionResult> DeleteUser(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    success = false,
                    message = "User not found"
                });
            }
            
            var currentUserId = GetCurrentUserId();
            if (user.Id == currentUserId)
            {
                return BadRequest(new ApiResponse<object>
                {
                    success = false,
                    message = "You cannot delete your own admin account from this endpoint"
                });
            }

            var result = await _userManager.DeleteAsync(user);
            if (result.Succeeded)
            {
                return Ok(new ApiResponse<object>
                {
                    success = true,
                    message = "User deleted successfully"
                });
            }

            return UnprocessableEntity(new ApiResponse<object>
            {
                success = false,
                message = "User deletion failed",
                errors = result.Errors.Select(e => e.Description).ToList()
            });
        }

        // POST: api/Admin/assign-role
        [HttpPost("assign-role")]
        public async Task<IActionResult> AssignRole([FromBody] AssignRoleRequest model)
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

            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    success = false,
                    message = "User not found"
                });
            }

            if (!await _roleManager.RoleExistsAsync(model.Role))
            {
                return BadRequest(new ApiResponse<object>
                {
                    success = false,
                    message = $"Role '{model.Role}' does not exist"
                });
            }

            if (await _userManager.IsInRoleAsync(user, model.Role))
            {
                return BadRequest(new ApiResponse<object>
                {
                    success = false,
                    message = $"User already has the '{model.Role}' role"
                });
            }

            var result = await _userManager.AddToRoleAsync(user, model.Role);
            if (result.Succeeded)
            {
                return Ok(new ApiResponse<object>
                {
                    success = true,
                    message = $"Role '{model.Role}' assigned to user successfully"
                });
            }
            
            return UnprocessableEntity(new ApiResponse<object>
            {
                success = false,
                message = "Role assignment failed",
                errors = result.Errors.Select(e => e.Description).ToList()
            });
        }

        // POST: api/Admin/remove-role
        [HttpPost("remove-role")]
        public async Task<IActionResult> RemoveRole([FromBody] RemoveRoleRequest model)
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

            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    success = false,
                    message = "User not found"
                });
            }

            if (!await _userManager.IsInRoleAsync(user, model.Role))
            {
                return BadRequest(new ApiResponse<object>
                {
                    success = false,
                    message = $"User does not have the '{model.Role}' role"
                });
            }

            var result = await _userManager.RemoveFromRoleAsync(user, model.Role);
            if (result.Succeeded)
            {
                return Ok(new ApiResponse<object>
                {
                    success = true,
                    message = $"Role '{model.Role}' removed from user successfully"
                });
            }
            
            return UnprocessableEntity(new ApiResponse<object>
            {
                success = false,
                message = "Role removal failed",
                errors = result.Errors.Select(e => e.Description).ToList()
            });
        }

        // GET: api/Admin/roles
        [HttpGet("roles")]
        public async Task<IActionResult> GetAllRoles()
        {
            var roles = await _roleManager.Roles.Select(r => r.Name).ToListAsync();

            return Ok(new ApiResponse<List<string?>>
            {
                success = true,
                message = "Roles retrieved successfully",
                data = roles
            });
        }

        // POST: api/Admin/users/{id}/lock
        [HttpPost("users/{id}/lock")]
        public async Task<IActionResult> LockUser(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    success = false,
                    message = "User not found"
                });
            }

            var currentUserId = GetCurrentUserId();
            if (user.Id == currentUserId)
            {
                return BadRequest(new ApiResponse<object>
                {
                    success = false,
                    message = "You cannot lock your own account"
                });
            }

            var result = await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddYears(1));
            if (result.Succeeded)
            {
                user.RefreshToken = null;
                user.RefreshTokenExpiryTime = null;
                await _userManager.UpdateAsync(user);

                return Ok(new ApiResponse<object>
                {
                    success = true,
                    message = "User account locked successfully"
                });
            }

            return UnprocessableEntity(new ApiResponse<object>
            {
                success = false,
                message = "Account lock failed",
                errors = result.Errors.Select(e => e.Description).ToList()
            });
        }

        // POST: api/Admin/users/{id}/unlock
        [HttpPost("users/{id}/unlock")]
        public async Task<IActionResult> UnlockUser(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    success = false,
                    message = "User not found"
                });
            }

            var result = await _userManager.SetLockoutEndDateAsync(user, null);
            if (result.Succeeded)
            {
                await _userManager.ResetAccessFailedCountAsync(user);

                return Ok(new ApiResponse<object>
                {
                    success = true,
                    message = "User account unlocked successfully"
                });
            }

            return UnprocessableEntity(new ApiResponse<object>
            {
                success = false,
                message = "Account unlock failed",
                errors = result.Errors.Select(e => e.Description).ToList()
            });
        }

        // POST: api/Admin/send-reset-password/{id}
        [HttpPost("send-reset-password/{id}")]
        public async Task<IActionResult> SendResetPasswordEmail(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound(new ApiResponse<object>
                {
                    success = false,
                    message = "User not found"
                });
            }

            if (string.IsNullOrEmpty(user.Email))
            {
                return BadRequest(new ApiResponse<object>
                {
                    success = false,
                    message = "User does not have an email address"
                });
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = Uri.EscapeDataString(token);
            var appUrl = _configuration["AppUrl"] ?? "https://localhost:7122";
            var resetLink = $"{appUrl}/api/UserManagement/reset-password?email={Uri.EscapeDataString(user.Email)}&token={encodedToken}";

            await _emailService.SendEmailAsync(
                user.Email,
                "Reset your password",
                $"<h2>Password Reset</h2>" +
                $"<p>An administrator has requested a password reset for your account.</p>" +
                $"<p>Click the link below to set a new password:</p>" +
                $"<a href=\"{resetLink}\" style='display:inline-block;padding:10px 20px;background:#007bff;color:#fff;text-decoration:none;border-radius:5px;'>Reset Password</a>" +
                $"<p style='margin-top:16px;color:#666;'>If you did not expect this, please contact your administrator.</p>"
            );

            // Revoke refresh token so the user must re-login after resetting
            user.RefreshToken = null;
            user.RefreshTokenExpiryTime = null;
            await _userManager.UpdateAsync(user);

            return Ok(new ApiResponse<object>
            {
                success = true,
                message = "Password reset email sent to user successfully"
            });
        }
    }
}
