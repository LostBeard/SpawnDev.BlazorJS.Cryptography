using SpawnDev.BlazorJS;
using SpawnDev.BlazorJS.Cryptography;
using SpawnDev.BlazorJS.Cryptography.Demo.Components;

var builder = WebApplication.CreateBuilder(args);

// Add BlazorJSRuntime service
builder.Services.AddBlazorJSRuntime();

// Crypto for the server. Uses System.Security.Cryptography.
builder.Services.AddSingleton<DotNetCrypto>();

// Crypto for the browser. Uses the browser's SubtleCrypto API.
// Used on server for server side rendering
builder.Services.AddScoped<BrowserCrypto>();

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents()
    .AddInteractiveWebAssemblyComponents();

builder.Services.AddControllers();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseWebAssemblyDebugging();
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.MapControllers();

app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode()
    .AddInteractiveWebAssemblyRenderMode()
    .AddAdditionalAssemblies(typeof(SpawnDev.BlazorJS.Cryptography.Demo.Client._Imports).Assembly);

app.Run();
