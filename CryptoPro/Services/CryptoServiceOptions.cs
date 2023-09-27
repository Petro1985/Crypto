using System.Security.Cryptography.X509Certificates;

namespace CryptoPro.Services;

public class CryptoServiceOptions
{
    public const string ConfigSectionName = "CryptoServiceOptions";
    
    public string ContentRef { get; set; }
    public string SignRefTagName { get; set; }
    public string SignatureMethod { get; set; }
    public string CanonicalizationMethod { get; set; }
    public string DigestMethod { get; set; }
    public string[] Transforms { get; set; }
    public StoreName StoreName { get; set; }
    public StoreLocation StoreLocation { get; set; }
}