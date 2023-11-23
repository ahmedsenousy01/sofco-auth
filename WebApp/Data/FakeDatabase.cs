namespace WebApp.Data;

public static class FakeDatabase
{
    public static List<User> Users { get; set; } =
    [
        new User()
        {
            GivenName = "John",
            FamilyName = "Doe",
            Email = "admin@sofco.org",
            Password = "admin"
        }
    ];

    public static List<Client> Clients { get; set; } =
    [
        new Client()
        {
            ClientId = "testclientid",
            ClientSecret = "testclientsecrettestclientsecret",
            ClientName = "Sofco Pay"
        },
        new Client()
        {
            ClientId = "testclientid2",
            ClientSecret = "testclientsecrettestclientsecret2",
            ClientName = "Sofco SMS"
        }
    ];

    public static Dictionary<string, List<AuthCode>> ClientAuthCodes { get; set; } = new()
    {
        [Clients[0].ClientId] = [new AuthCode() { Code = "b1409991-7c7a-4bd6-b434-60016740c6d1" }],
        [Clients[1].ClientId] = [new AuthCode() { Code = "0c6f3acf-56bd-4cae-8ab2-8f581905a2bd" }]
    };

    public static Dictionary<string, List<CodeChallenge>> AuthCodeCodeChallenges { get; set; } = [];

    public static Dictionary<string, List<Token>> AuthCodeGeneratedTokens { get; set; } = [];
}
