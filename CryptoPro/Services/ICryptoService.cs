using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CryptoPro.Services;

public interface ICryptoService
{
    public X509Certificate2? GetCertificateByName(string certName);
    MemoryStream SignXmlFile(Stream xmlContentStream, X509Certificate2  key);
    
    /// <summary>
    /// Возвращает имена всех действующих сертификатов в хранилище.
    /// </summary>
    /// <returns>Коллекция сертификатов</returns>
    IEnumerable<string> GetAllCertificateNames();

    public bool VerifyXmlFile(Stream xmlContentStream, X509Certificate2 cert);
}