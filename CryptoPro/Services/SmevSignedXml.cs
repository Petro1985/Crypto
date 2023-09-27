using System.Security.Cryptography.Xml;
using System.Xml;

namespace CryptoPro.Services;

class SmevSignedXml : SignedXml
{
    public SmevSignedXml(XmlDocument document)
        : base(document)
    {
    }
 
    public override XmlElement? GetIdElement(XmlDocument document, string idValue)
    {
        var manager = new XmlNamespaceManager(new NameTable());
        manager.AddNamespace("soapenv", "http://schemas.xmlsoap.org/soap/envelope/");
        manager.AddNamespace("ns1", "urn://x-artefacts-mcx-gov-ru/fgiz-zerno/api/ws/types/1.0.5");
        return document.SelectSingleNode($"//ns1:MessageData[@Id='{idValue}']", manager) as XmlElement;
    }
}