namespace WebApp;

public class Token
{
    public string Type { get; set; }
    public string TokenString { get; set; }
    public bool Revoked { get; set; } = false;
}
