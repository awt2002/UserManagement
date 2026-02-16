using System.ComponentModel.DataAnnotations;

namespace UserManagement.DTOs.Auth
{
    // DTO for user registration request
    public class RegisterRequestDto
    {
        // Name field with required validation
        [Required(ErrorMessage = "Name is required")]
        public string Name { get; set; } = string.Empty;

        // Email field with validation
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        public string Email { get; set; } = string.Empty;

        // Password field with complexity requirements
        [Required(ErrorMessage = "Password is required")]
        [MinLength(8, ErrorMessage = "Password must be at least 8 characters")]
        [RegularExpression(
            @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).+$",
            ErrorMessage = "Password must contain uppercase, lowercase, number and special character"
        )]
        public string Password { get; set; } = string.Empty;

        // Confirm password field to match the password
        [Required(ErrorMessage = "Confirm password is required")]
        [Compare("Password", ErrorMessage = "Passwords do not match")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }
}
