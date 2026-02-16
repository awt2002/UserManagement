using System.ComponentModel.DataAnnotations;

namespace UserManagement.DTOs.Auth
{
    public class LoginRequestDto
    {
        // Email field with validation
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        public string Email { get; set; } = "";

        // Password field with required validation
        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; } = "";
    }
}
