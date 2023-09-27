using CryptoPro.Authentication;
using CryptoPro.Services;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

// Инициализация библиотеки для работы с ЭЦП
LibCore.Initializer.Initialize(LibCore.Initializer.DetouredAssembly.Xml);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services
    .AddAuthentication("ApiKey")
    .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>("ApiKey", null);

builder.Services.AddOptions<CryptoServiceOptions>()
    .BindConfiguration(CryptoServiceOptions.ConfigSectionName);
builder.Services.AddScoped<ICryptoService, CryptoService>();

var app = builder.Build();
app.UseAuthentication();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();