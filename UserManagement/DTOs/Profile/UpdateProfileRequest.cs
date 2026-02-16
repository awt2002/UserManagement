using System.ComponentModel.DataAnnotations;

namespace UserManagement.DTOs.Profile
{
    // DTO for updating user profile information
    public class UpdateProfileRequest
    {
        // Name field for updating user's name
        [Required(ErrorMessage = "Name is required")]
        public string? Name { get; set; }
    }
}