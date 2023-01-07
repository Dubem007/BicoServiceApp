using BicoAuthService.Data.DbContext;
using BicoAuthService.Entities.Identity;
using BicoAuthService.Helpers;
using BicoAuthService.Interface;
using BicoAuthService.Logger;
using BicoAuthService.Services;
using BicoAuthService.Shared.Utils.Email;
using Hangfire;
using AutoMapper;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;
using System.Text;
using BicoAuthService.Middlewares;
using FluentValidation.AspNetCore;
using System.Reflection;
using FluentValidation;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Http;

namespace BicoAuthService.Extensions
{
    public static class ServiceExtensions
    {
        public static void ConfigureCors(this IServiceCollection services)
        {
            services.AddCors(options => options.AddPolicy("CorsPolicy",
                builder =>
                {
                    builder.AllowAnyHeader()
                           .AllowAnyMethod()
                           .SetIsOriginAllowed((host) => true)
                           .AllowCredentials();
                }));
        }

        public static void ConfigureLoggerService(this IServiceCollection services)
        {
            services.AddSingleton<ILoggerManager, LoggerManager>();
        }


        public static void ConfigureIisIntegration(this IServiceCollection serviceCollection) =>
            serviceCollection.Configure<IISOptions>(options => { });

        public static void ConfigureMsSqlContext(this IServiceCollection serviceCollection, IConfiguration configuration)
        {
            //var server = configuration.GetSection("Connections:DBServer").Value;
            //var port = configuration.GetSection("Connections:DBPort").Value;
            //var user = configuration.GetSection("Connections:DBUser").Value;
            //var password = configuration.GetSection("Connections:DBPassword").Value;
            //var databse = configuration.GetSection("Connections:Database").Value;
            //var certificate = configuration.GetSection("Connections:DBCertificate").Value;
            //var security = configuration.GetSection("Connections:DBSecurity").Value;
            //var resultset = configuration.GetSection("Connections:DBResultSets").Value;
            serviceCollection.AddDbContext<AppDbContext>(
              opts =>
              {
                  //opts.UseSqlServer($"Server ={server},{port};Initial Catalog={databse};User ID={user};Password={password};MultipleActiveResultSets={resultset}");
                  opts.UseSqlServer(configuration.GetConnectionString("DefaultConnection"));
              });
        }

        //public static void ConfigureIOObjects(this IServiceCollection services, IConfiguration configuration)
        //{
        //    services.Configure<AwsConfiguration>(configuration.GetSection("AWS"));
        //    services.Configure<FileSettings>(configuration.GetSection(nameof(FileSettings)));
        //    services.Configure<SmtpSettings>(configuration.GetSection(nameof(SmtpSettings)));
        //}

        public static void ConfigureJwt(this IServiceCollection services, IConfiguration configuration)
        {
            var jwtSettings = configuration.GetSection("JwtSettings");
            var jwtUserSecret = jwtSettings.GetSection("Secret").Value;

            services.AddAuthentication(opt =>
            {
                opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(options =>
            {
                options.RequireHttpsMetadata = false;
                options.SaveToken = true;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtSettings.GetSection("ValidIssuer").Value,
                    ValidAudience = jwtSettings.GetSection("ValidAudience").Value,
                    IssuerSigningKey = new
                        SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtUserSecret))
                };
               
            });
        }

        //public static void ConfigureRedis(this IServiceCollection services, IConfiguration configuration)
        //{
        //    services.AddSingleton<IConnectionMultiplexer>(sp =>
        //    {
        //        var configurationOptions = ConfigurationOptions.Parse(configuration.GetConnectionString("RedisConnection"), true);
        //        return ConnectionMultiplexer.Connect(configurationOptions);
        //    });
        //}

       
        //public static void ConfigureHangFire(this IServiceCollection services, IConfiguration configuration)
        //{
        //    services.AddHangfire(config =>
        //        config(configuration.GetConnectionString("HangFireConnection")));
        //    services.AddHangfireServer();
        //}

        public static void ConfigureAWSServices(this IServiceCollection services, IConfiguration configuration)
        {
            //services.AddTransient<IAwsS3Client, AwsS3Client>();
            services.AddTransient<IWebHelper, WebHelper>();
            services.AddScoped<IAuthentication, Authentication>();
            services.AddScoped<IToken, TokenService>();
            services.AddScoped<IUserActivityRepository, UserActivityService>();
            services.AddScoped<IUserRepository, UserRepository>();
            //services.AddTransient<ICacheServices, CacheServices>();
           
        }

        public static void ConfigureAppServices(this IServiceCollection services)
        {
            services.AddScoped<IEmailManager, EmailManager>();
           // services.AddHttpClient<FcmSender>();
            //services.AddScoped<IEmailClient, EmailClient>();
        }

        public static void ConfigureApiVersioning(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddApiVersioning(opt =>
            {
                opt.AssumeDefaultVersionWhenUnspecified = true;
                opt.DefaultApiVersion = new ApiVersion(1, 0);
                opt.ReportApiVersions = true;
            });
            services.AddVersionedApiExplorer(opt =>
            {
                opt.GroupNameFormat = "'v'VVV";
                opt.SubstituteApiVersionInUrl = true;
            });
            services.AddTransient<IConfigureOptions<SwaggerGenOptions>, ConfigureSwaggerOptions>();
            services.AddMvcCore().AddApiExplorer();
        }

        public static void ConfigureSwagger(this IServiceCollection services)
        {
            services.AddSwaggerGen(c =>
            {
                c.OperationFilter<RemoveVersionFromParameter>();
                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Name = "Authorization",
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "Bearer",
                    BearerFormat = "JWT",
                    In = ParameterLocation.Header,
                    Description = "JWT Authorization header using the Bearer scheme."
                });

                c.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        }
                    },
                    new string[] {}
                }
            });
            });
        }

        public static void ConfigureIdentity(this IServiceCollection services)
        {
            var builder = services.AddIdentity<User, Role>(opt =>
            {
                opt.Password.RequireDigit = true;
                opt.Password.RequireLowercase = true;
                opt.Password.RequireUppercase = true;
                opt.Password.RequireNonAlphanumeric = false;
                opt.Password.RequiredLength = 8;
                opt.User.RequireUniqueEmail = false;
                opt.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@/";
                
            })
                .AddEntityFrameworkStores<AppDbContext>()
                .AddDefaultTokenProviders();

        }

        public static void ConfigureMvc(this IServiceCollection services)
        {
            services.AddMvc()
                .ConfigureApiBehaviorOptions(o =>
                {
                    o.InvalidModelStateResponseFactory = context => new ValidationFailedResult(context.ModelState);
                }).AddFluentValidation(options =>
                {
                    // Validate child properties and root collection elements
                    options.ImplicitlyValidateChildProperties = true;
                    options.ImplicitlyValidateRootCollectionElements = true;

                    // Automatic registration of validators in assembly
                    options.RegisterValidatorsFromAssembly(Assembly.GetExecutingAssembly());
                }); ;

        }


        public static void ConfigureHangFire(this IServiceCollection services, IConfiguration configuration)
        {
            //var server = configuration.GetSection("Connections:DBServer").Value;
            //var port = configuration.GetSection("Connections:DBPort").Value;
            //var user = configuration.GetSection("Connections:DBUser").Value;
            //var password = configuration.GetSection("Connections:DBPassword").Value;
            //var databse = configuration.GetSection("Connections:Database").Value;
            //var certificate = configuration.GetSection("Connections:DBCertificate").Value;
            //var security = configuration.GetSection("Connections:DBSecurity").Value;
            //var resultset = configuration.GetSection("Connections:DBResultSets").Value;
            services.AddHangfire(config =>
           // config.UseSqlServerStorage($"Server ={server},{port};Initial Catalog={databse};User ID={user};Password={password};MultipleActiveResultSets={resultset}"));
            config.UseSqlServerStorage(configuration.GetConnectionString("HangFireConnection")));
            services.AddHangfireServer();
        }
    }
}
