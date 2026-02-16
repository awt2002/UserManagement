using System.ComponentModel.DataAnnotations;

namespace UserManagement.DTOs.Auth
{
    public class ChangePasswordRequest
    {
        // Current Password field with required validation
        [Required(ErrorMessage = "Current Password is required")]
        public string CurrentPassword { get; set; } = string.Empty;

        // New Password field with complexity requirements
        [Required(ErrorMessage = " New Password is required")]
        [MinLength(8, ErrorMessage = "Password must be at least 8 characters")]
        [RegularExpression(
            @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).+$",
            ErrorMessage = "Password must contain uppercase, lowercase, number and special character"
        )]
        public string NewPassword { get; set; } = string.Empty;

        // Confirm New Password field to match the New Password
        [Required(ErrorMessage = "Confirm New password is required")]
        [Compare("NewPassword", ErrorMessage = "Passwords do not match")]
        public string ConfirmNewPassword { get; set; } = string.Empty;
    }

    public class RestorePasswordRequest
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        public string Email { get; set; } = string.Empty;
    }
}
