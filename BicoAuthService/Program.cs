using Autofac.Core;
using BicoAuthService.Data;
using BicoAuthService.Data.DbContext;
using BicoAuthService.Data.DbSeeds;
using BicoAuthService.Extensions;
using BicoAuthService.Helpers;
using Hangfire;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.ConfigureCors();
builder.Services.ConfigureIisIntegration();
builder.Services.ConfigureIdentity();
builder.Services.ConfigureLoggerService();
builder.Services.ConfigureMsSqlContext(builder.Configuration);
builder.Services.AddAuthentication();
builder.Services.ConfigureJwt(builder.Configuration);
builder.Services.AddHttpContextAccessor();
builder.Services.ConfigureAppServices();
builder.Services.ConfigureAWSServices(builder.Configuration);
builder.Services.AddControllers()
    .AddXmlDataContractSerializerFormatters();
builder.Services.ConfigureSwagger();
builder.Services.ConfigureApiVersioning(builder.Configuration);
//builder.Services.ConfigureRedis(builder.Configuration);

builder.Services.ConfigureHangFire(builder.Configuration);
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());

var app = builder.Build();
app.SeedRoleData().Wait();
//PrepDB.prepopulation(app); 
var apiVersionDescriptionProvider = app.Services.GetRequiredService<IApiVersionDescriptionProvider>();
if (app.Environment.IsProduction())
{
    app.UseHsts();
}

app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.ConfigObject.AdditionalItems.Add("persistAuthorization", "true");
    foreach (var description in apiVersionDescriptionProvider.ApiVersionDescriptions.Reverse())
    {
        c.SwaggerEndpoint($"/swagger/{description.GroupName}/swagger.json",
            description.GroupName.ToUpperInvariant());
    }
});
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseCors("CorsPolicy");

app.UseAuthentication();
app.UseAuthorization();

if (app.Environment.IsDevelopment())
{
    app.UseHangfireDashboard();
}
else
{
    app.UseHangfireDashboard("/hangfire", new DashboardOptions
    {
        Authorization = new[] { new HangFireAuthorizationFilter(builder.Configuration) }
    });
}
//app.UseErrorHandler();
app.MapControllers();
app.UseEndpoints(endpoints =>
{
    endpoints.MapControllers();
});
WebHelper.Configure(app.Services.GetRequiredService<IHttpContextAccessor>());

// migrate any database changes on startup
using (var scope = app.Services.CreateScope())
{
    var dataContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    System.Console.WriteLine("Applying Migrations.........");
    dataContext.Database.Migrate();
    System.Console.WriteLine("Concluded Migrations.........");
}
app.Run();