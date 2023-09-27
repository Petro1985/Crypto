// using System.Security.Cryptography;
// using System.Security.Cryptography.X509Certificates;
// using System.Security.Cryptography.Xml;
// using System.Xml;
//
// public class qwe
// {
//     static string getSignXmlFile(string textXmlFile, AsymmetricAlgorithm Key, X509Certificate Certificate,
//         bool isResponse = false)
//     {
//         if (isResponse)
//             textXmlFile = textXmlFile.Replace("SendRequestRequest", "SendResponseRequest"); // Замена типа запроса
//
//
//         XmlDocument doc = new XmlDocument(); // Создаем новый XML документ.
//         doc.PreserveWhitespace =
//             true; // Пробельные символы участвуют в вычислении подписи и должны быть сохранены для совместимости с другими реализациями.
//         //doc.Load(new XmlTextReader(FileName)); // Читаем документ из файла.
//         doc.LoadXml(textXmlFile); // Читаем документ из строки
//
//         if (isResponse)
//         {
//             XmlNode MessagePrimaryContent = doc.SelectSingleNode("//*[local-name()='MessagePrimaryContent']");
//             doc.SelectSingleNode("//*[local-name()='MessageData']").RemoveChild(MessagePrimaryContent);
//         }
//
//         SignedXml signedXml = new SignedXml(doc); // Создаем объект SignedXml по XML документу.
//         signedXml.SigningKey = Key; // Добавляем ключ в SignedXml документ. 
//
//
//         Reference reference = new Reference();
//         reference.Uri = "#SIGNED_BY_CALLER"; // Создаем ссылку на node для подписи.
//
//         // Проставляем алгоритм хэширования
//         reference.DigestMethod = CPSignedXml.XmlDsigGost3411_2012_256Url; // CryptoPro.Sharpei.Xml
//
//         // Добавляем transform для канонизации.
//         var c14 = new XmlDsigExcC14NTransform();
//         reference.AddTransform(c14);
//
//         // Добавляем СМЭВ трансформ.
//         // начиная с .NET 4.5.1 для проверки подписи, необходимо добавить этот трансформ в довернные:
//         // signedXml.SafeCanonicalizationMethods.Add("urn://smev-gov-ru/xmldsig/transform");
//         var smev = new XmlDsigSmevTransform(); // CryptoPro.Sharpei.Xml
//         reference.AddTransform(smev);
//
//         signedXml.AddReference(reference); // Добавляем ссылку на подписываемые данные
//
//         KeyInfo keyInfo = new KeyInfo(); // Создаем объект KeyInfo.
//
//         keyInfo.AddClause(new KeyInfoX509Data(Certificate)); // Добавляем сертификат в KeyInfo
//
//         signedXml.KeyInfo = keyInfo; // Добавляем KeyInfo в SignedXml.
//
//         // Алгоритм подписи берётся автоматически (из ключа)
//         //signedXml.SignedInfo.SignatureMethod = CPSignedXml.XmlDsigGost3411_2012_256HMACUrl;
//         signedXml.SignedInfo.CanonicalizationMethod = c14.Algorithm;
//
//         signedXml.ComputeSignature(); // Вычисляем подпись.
//
//         XmlElement
//             xmlDigitalSignature =
//                 signedXml.GetXml(); // Получаем XML представление подписи и сохраняем его в отдельном node.
//
//         doc.SelectSingleNode("//*[local-name()='InformationSystemSignature']")
//             .AppendChild(doc.ImportNode(xmlDigitalSignature, true));
//
//
//         // При наличии стартовой XML декларации ее удаляем
//         // (во избежание повторного сохранения)
//         if (doc.FirstChild is XmlDeclaration)
//         {
//             doc.RemoveChild(doc.FirstChild);
//         }
//
//         /*
//         // Сохраняем подписанный документ в файле.
//         using (XmlTextWriter xmltw = new XmlTextWriter(SignedFileName, new UTF8Encoding(false)))
//         {
//             xmltw.WriteStartDocument();
//             doc.WriteTo(xmltw);
//         }
//         */
//
//         // Сохраняем подписанный документ в строке и возвращаем
//         using (var stringWriter = new StringWriter())
//         using (var xmlTextWriter = XmlWriter.Create(stringWriter))
//         {
//             doc.WriteTo(xmlTextWriter);
//             xmlTextWriter.Flush();
//             return stringWriter.GetStringBuilder().ToString();
//         }
//     }
// }