namespace KPO_2
{
    public class RegistrationRequest
    {
        public string? Name { get; set; }
        public string? Email { get; set; }
        public string? Password { get; set; }
    }

    public class UserAuthorizationRequest
    {
        public string? Email { get; set; }
        public string? Password { get; set; }
    }

    public class ChangeRoleRequest
    {
        public string? Email { get; set; }
    }
}