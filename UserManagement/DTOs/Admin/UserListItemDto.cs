namespace UserManagement.DTOs.Admin
{
    public class UserListItemDto
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public bool EmailConfirmed { get; set; }
        public bool IsLockedOut { get; set; }
        public List<string> Roles { get; set; } = new();
    }
}
