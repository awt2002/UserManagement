namespace UserManagement.DTOs.Common
{
    // Standard API response structure
    public class ApiResponse<T>
    {
        public bool success { get; set; }
        public string message { get; set; } = string.Empty;
        public T? data { get; set; }
        public List<string>? errors { get; set; }
    }
}
