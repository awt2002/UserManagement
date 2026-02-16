using System.ComponentModel.DataAnnotations;

namespace UserManagement.DTOs.Auth
{
    public class RefreshTokenRequest
    {
        [Required(ErrorMessage = "Token is required")]
        public string Token { get; set; } = string.Empty;
    }
}
