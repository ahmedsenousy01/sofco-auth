namespace WebApp.Data;

public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string GivenName { get; set; }
    public string FamilyName { get; set; }
    public string FullName => GivenName + " " + FamilyName;
    public string Email { get; set; }
    public string Password { get; set; }
}
