using SpawnDev.BlazorJS;
using SpawnDev.BlazorJS.Cryptography;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

// Add BlazorJSRuntime service
builder.Services.AddBlazorJSRuntime();

// Add PortableCrypto service
builder.Services.AddSingleton<PortableCrypto>();

var app = builder.Build();

// Configure the HTTP request pipeline.

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
