using System.ComponentModel.DataAnnotations;

namespace UserManagement.DTOs.Admin
{
    public class AssignRoleRequest
    {
        [Required(ErrorMessage = "User ID is required")]
        public string UserId { get; set; } = string.Empty;

        [Required(ErrorMessage = "Role is required")]
        public string Role { get; set; } = string.Empty;
    }
}
