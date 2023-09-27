using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Linq;
using LibCore.Security.Cryptography.X509Certificates;
using LibCore.Security.Cryptography.Xml;
using LibCore.Security.Cryptography.Xml.Detours;
using Microsoft.Extensions.Options;

namespace CryptoPro.Services;

public class CryptoService : ICryptoService
{
    private CryptoServiceOptions _options;
    
    private readonly Dictionary<string, string> _signatureMethods = new ()
    {
        {"ГОСТ Р 34.10-2012, 256", CpSignedXml.XmlDsigGost3410_2012_256Url},
        {"ГОСТ Р 34.10-2012, 512", CpSignedXml.XmlDsigGost3410_2012_512Url},
        {"ГОСТ Р 34.11-2012, 256", CpSignedXml.XmlDsigGost3411_2012_256Url},
        {"ГОСТ Р 34.11-2012, 512", CpSignedXml.XmlDsigGost3411_2012_512Url},
    }; 
    
    private readonly Dictionary<string, string> _canonicalizationMethods = new ()
    {
        {"XMLDSig", SignedXml.XmlDsigExcC14NTransformUrl},
    }; 
    
    private readonly Dictionary<string, string> _digestMethods = new ()
    {
        {"ГОСТ Р 34.10-2012, 256", CpSignedXml.XmlDsigGost3410_2012_256Url},
        {"ГОСТ Р 34.10-2012, 512", CpSignedXml.XmlDsigGost3410_2012_512Url},
        {"ГОСТ Р 34.11-2012, 256", CpSignedXml.XmlDsigGost3411_2012_256Url},
        {"ГОСТ Р 34.11-2012, 512", CpSignedXml.XmlDsigGost3411_2012_512Url},
    }; 

    public CryptoService(IOptions<CryptoServiceOptions> options)
    {
        _options = options.Value;
    }

    /// <summary>
    /// Поиск сертификата по имени
    /// </summary>
    /// <param name="certName">Полное или частичное имя сертификата</param>
    /// <returns></returns>
    public X509Certificate2? GetCertificateByName(string certName)
    {
        using var store = new X509Store(_options.StoreName, _options.StoreLocation);
        store.Open(OpenFlags.ReadOnly);
        var certificates = store.Certificates.Find(X509FindType.FindBySubjectName, certName, true);
        if (certificates.Count > 1)
        {
            throw new Exception("Найдено более одного сертификата подходящего по имени, уточните запрос." +
                                $"{Environment.NewLine}найденные сертификаты:{Environment.NewLine}{string.Join(Environment.NewLine, certificates.Select(x => x.SubjectName.Name))}");
        }
        return certificates.FirstOrDefault();
    }
    
    /// <summary>
    /// Метод для подписи XML файла.
    /// </summary>
    /// <param name="xmlFileContent">Соержимое xml файла</param>
    /// <param name="cert">Сертификат</param>
    public MemoryStream SignXmlFile(Stream xmlContentStream, X509Certificate2  cert)
    {
        // Create a new XML document.
        XmlDocument doc = new XmlDocument();

        // Пробельные символы участвуют в вычислении подписи и должны быть сохранены для совместимости с другими реализациями.
        doc.PreserveWhitespace = true;
        // Load the passed XML file using its name.
        doc.Load(xmlContentStream);

        // Create a SignedXml object.
        SignedXml signedXml = new SmevSignedXml(doc);
        
        // Пытаемся получить Private Key
        var key = cert.GetGost3410_2012_256PrivateKey();
        if (key is null)
            throw new Exception($"Не удалось получить закрытый ключ из сертификата {cert.FriendlyName}");
            
        // Add the key to the SignedXml document. 
        signedXml.SigningKey = key;
        
        // Создаем ссылку на данные которые будут подписываться
        var reference = new Reference
        {
            Uri = _options.ContentRef,
        };

        if (!_digestMethods.TryGetValue(_options.DigestMethod, out var digestMethod))
        {
            var message = $"Не удалось найти DigestMethod '{_options.DigestMethod}'\n" +
                          $"Поддерживаемые варианты:\n" + string.Join("\n", _digestMethods.Keys);
            throw new Exception(message);
        }
        reference.DigestMethod = digestMethod;

        // Add an enveloped transformation to the reference.
        signedXml.SafeCanonicalizationMethods.Add("urn://smev-gov-ru/xmldsig/transform");
        // var env = new XmlDsigEnvelopedSignatureTransform();
        // reference.AddTransform(env);
        var smev = new XmlDsigSmevTransform();
        reference.AddTransform(smev);
        
        // var c14 = new XmlDsigExcC14NTransform();
        // reference.AddTransform(c14);
        // XmlDsigC14NTransform c14 = new XmlDsigC14NTransform();
        // reference.AddTransform(c14);
        
        KeyInfo keyInfo = new KeyInfo(); // Создаем объект KeyInfo.
        keyInfo.AddClause(new KeyInfoX509Data(cert)); // Добавляем сертификат в KeyInfo
        signedXml.KeyInfo = keyInfo; // Добавляем KeyInfo в SignedXml.
        
        if (!_canonicalizationMethods.TryGetValue(_options.CanonicalizationMethod, out var canonicalizationMethod))
        {
            var message = $"Не удалось найти CanonicalizationMethod '{_options.CanonicalizationMethod}'\n" +
                          $"Поддерживаемые варианты:\n" + string.Join("\n", _canonicalizationMethods.Keys);
            throw new Exception(message);
        }
        signedXml.SignedInfo.CanonicalizationMethod = canonicalizationMethod;
        
        if (!_signatureMethods.TryGetValue(_options.SignatureMethod, out var signatureMethod))
        {
            var message = $"Не удалось найти SignatureMethod '{_options.SignatureMethod}'\n" +
                          $"Поддерживаемые варианты:\n" + string.Join("\n", _signatureMethods.Keys);
            throw new Exception(message);
        }
        signedXml.SignedInfo.SignatureMethod = signatureMethod;
        
        // Add the reference to the SignedXml object.
        signedXml.AddReference(reference);

        // Compute the signature.
        signedXml.ComputeSignature();

        // Get the XML representation of the signature and save
        // it to an XmlElement object.
        var xmlDigitalSignature = signedXml.GetXml();
        var signaturePlace = doc.GetElementsByTagName("ns1:InformationSystemSignature")[0];
        signaturePlace.RemoveAll();
        signaturePlace.AppendChild(doc.ImportNode(xmlDigitalSignature, true));

        // var signatureValue = xmlDigitalSignature.GetElementsByTagName("SignatureValue")[0];
        // var signedInfo = xmlDigitalSignature.GetElementsByTagName("SignedInfo")[0];
        //
        // var keyInfoXml = signedXml.KeyInfo.GetXml(); 
        // var signaturePlace = doc.GetElementsByTagName("Signature")[0];
        //
        // signaturePlace.AppendChild(
        //     doc.ImportNode(signedInfo, true));
        // signaturePlace.AppendChild(
        //     doc.ImportNode(signatureValue, true));
        // signaturePlace.AppendChild(
        //     doc.ImportNode(keyInfoXml, true));

        
        // При наличии стартовой XML декларации ее удаляем
        // (во избежание повторного сохранения)
        // if (doc.FirstChild is XmlDeclaration)
        // {
        //     doc.RemoveChild(doc.FirstChild);
        // }
        
        // Сохраняем подписанный Xml в stream
        var memoryStream = new MemoryStream();
        doc.Save(memoryStream);
        memoryStream.Position = 0;
        return memoryStream;
    }

    private void SetNewPrefix(XmlNode node, string prefix)
    {
        node.Prefix = prefix;
        foreach (XmlNode childNode in node.ChildNodes)
        {
            SetNewPrefix(childNode, prefix);
        }
    }
    public IEnumerable<string> GetAllCertificateNames()
    {
        using var store = new X509Store(_options.StoreName, _options.StoreLocation);
        store.Open(OpenFlags.ReadOnly);
        return store.Certificates.Where(x => x.HasPrivateKey).Select(x => x.SubjectName.Name);
    }

    // Verify the signature of an XML file against an asymmetric 
    // algorithm and return the result.
    public bool VerifyXmlFile(Stream xmlContentStream, X509Certificate2 cert)
    {
        // Create a new XML document.
        XmlDocument xmlDocument = new XmlDocument();
        // Load the passed XML file into the document. 
        xmlDocument.Load(xmlContentStream);
        xmlContentStream.Position = 0;

        var xmlDocumentWithNs = new XmlDocument();
        xmlDocumentWithNs.Load(xmlContentStream);
        xmlContentStream.Position = 0;
        var signNode = xmlDocumentWithNs.GetElementsByTagName("Signature")[0];
        SetNewPrefix(signNode, "ds");
        
        // Create a new SignedXml object and pass it
        // the XML document class.
        
        SignedXml signedXml = new SignedXml(xmlDocument);
        SignedXml signedXml2 = new SignedXml(xmlDocumentWithNs);

        // Find the "Signature" node and create a new
        // XmlNodeList object.
        // XmlNodeList nodeList = xmlDocument.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl);
        XmlNodeList nodeList = xmlDocument.GetElementsByTagName("Signature");

        // Load the signature node.
        signedXml.LoadXml((XmlElement)nodeList[0]);
        signedXml2.LoadXml((XmlElement)signNode);

        // Check the signature and return the result.
        var result = signedXml.CheckSignature(cert.GetGost3410_2012_256PublicKey());
        var result2 = signedXml2.CheckSignature(cert.GetGost3410_2012_256PublicKey());
        return result;
    }
}