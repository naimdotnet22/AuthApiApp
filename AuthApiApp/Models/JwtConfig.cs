
namespace AuthApiApp.Models
{
    public class JwtConfig
    {
        public string Key { get; set; }
        public string ValidAudience { get; set; }
        public string ValidIssuer { get; set; }
    }
}
