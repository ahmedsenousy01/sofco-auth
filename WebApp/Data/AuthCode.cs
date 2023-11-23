namespace WebApp;

public class AuthCode
{
    public string Code = Guid.NewGuid().ToString();
    public DateTime Expiry { get; set; } = DateTime.Now.AddMinutes(10);
    public bool Revoked { get; set; } = false;
}
