using CryptoPro.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CryptoPro.Controllers;

[ApiController]
[Route("[controller]")]
public class CryptoController : ControllerBase
{
    private readonly ILogger<CryptoController> _logger;
    private readonly ICryptoService _cryptoService;

    public CryptoController(ILogger<CryptoController> logger, ICryptoService cryptoService)
    {
        _logger = logger;
        _cryptoService = cryptoService;
    }

    [HttpPost]
    [Route("sign")]
    [Authorize]
    [ProducesResponseType(typeof(string), 200)]
    public IActionResult SignXml([FromQuery] string certName)
    {
        if (string.IsNullOrWhiteSpace(certName))
        {
            return BadRequest("Необходимо задать query-параметр certName");
        }

        try
        {
            var cert = _cryptoService.GetCertificateByName(certName);
            if (cert is null)
                throw new Exception("Сертификат не найден");
        
            var contentStream = Request.BodyReader.AsStream();
            var signed = _cryptoService.SignXmlFile(contentStream, cert);


            if (!_cryptoService.VerifyXmlFile(signed, cert))
            {
                throw new Exception("Подпись не прошла валидацию");
            }

            Response.ContentType = "application/xml"; 
            return Ok(signed);
        }
        catch (Exception e)
        {
            return BadRequest(e.Message);
        }
    }

    [HttpGet]
    [Route("GetAllCertificates")]
    [Authorize]
    public IActionResult GetAllCertificates()
    {
        return Ok(_cryptoService.GetAllCertificateNames());
    }
}