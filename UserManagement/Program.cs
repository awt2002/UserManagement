using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using UserManagement.Data;
using UserManagement.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

var builder = WebApplication.CreateBuilder(args);

var jwtHandler = new JwtSecurityTokenHandler();

builder.Services.AddControllers();

builder.Services.AddOpenApi(options =>
{
    options.AddDocumentTransformer<UserManagement.OpenApi.BearerSecuritySchemeTransformer>();
});

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequiredLength = 8;
    options.Password.RequiredUniqueChars = 1;
    options.SignIn.RequireConfirmedEmail = true;
}).AddEntityFrameworkStores<ApplicationDbContext>()
  .AddDefaultTokenProviders();

builder.Services.AddScoped<IEmailService, SmtpEmailService>();

// Configure JWT Authentication
if (builder.Environment.IsDevelopment() || builder.Configuration.GetValue<bool>("Jwt:DebugShowPII"))
{
    Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
}
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.IncludeErrorDetails = true;
    var isDev = builder.Environment.IsDevelopment() || builder.Configuration.GetValue<bool>("Jwt:DebugShowPII");
    var jwtKey = builder.Configuration["Jwt:Key"];
    if (string.IsNullOrWhiteSpace(jwtKey))
    {
        throw new InvalidOperationException("Jwt:Key configuration value is missing or empty.");
    }
    var jwtIssuer = builder.Configuration["Jwt:Issuer"];
    var jwtAudience = builder.Configuration["Jwt:Audience"];
    var validateIssuer = !string.IsNullOrWhiteSpace(jwtIssuer) && !isDev;
    var validateAudience = !string.IsNullOrWhiteSpace(jwtAudience) && !isDev;
    var validateSigningKey = !isDev;
    var validateLifetime = !isDev;
    var keyBytes = System.Text.Encoding.UTF8.GetBytes(jwtKey);
    options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
    {
        ValidateIssuer = validateIssuer,
        ValidateAudience = validateAudience,
        ValidateLifetime = validateLifetime,
        ValidateIssuerSigningKey = validateSigningKey,
        NameClaimType = JwtRegisteredClaimNames.Sub,
        RoleClaimType = System.Security.Claims.ClaimTypes.Role,
        ValidIssuer = jwtIssuer,
        ValidAudience = jwtAudience,
        IssuerSigningKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(keyBytes)
    };
    options.SaveToken = true;
    options.RequireHttpsMetadata = !isDev;
    options.TokenValidationParameters.ClockSkew = TimeSpan.FromMinutes(1);

    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            // Pre-validate the Authorization header to avoid library decode errors for malformed tokens.
            var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
            if (string.IsNullOrEmpty(authHeader))
            {
                return Task.CompletedTask;
            }

            const string bearerPrefix = "Bearer ";
            if (!authHeader.StartsWith(bearerPrefix, StringComparison.OrdinalIgnoreCase))
            {
                return Task.CompletedTask;
            }

            var token = authHeader.Substring(bearerPrefix.Length).Trim();
            // Strip possible surrounding quotes or common bad client values
            token = token.Trim('"').Trim('\'');
            if (string.Equals(token, "null", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(token, "undefined", StringComparison.OrdinalIgnoreCase))
            {
                context.NoResult();
                return Task.CompletedTask;
            }

            // Use the JwtSecurityTokenHandler to quickly rule out tokens that cannot be read
            if (!jwtHandler.CanReadToken(token))
            {
                context.NoResult();
                return Task.CompletedTask;
            }

            context.Token = token;
            return Task.CompletedTask;
        },

        OnAuthenticationFailed = async context =>
        {
            var logger = context.HttpContext.RequestServices
                .GetRequiredService<ILoggerFactory>()
                .CreateLogger("JwtAuth");

            logger.LogError(context.Exception, "JWT authentication failed: {Message}", context.Exception.Message);
            // Log the token and failure details for debugging in Development.
            if (builder.Environment.IsDevelopment() || builder.Configuration.GetValue<bool>("Jwt:DebugShowPII"))
            {
                try
                {
                    var raw = context.Request.Headers["Authorization"].FirstOrDefault();
                    logger.LogDebug("JWT raw header: {Raw}", raw);
                }
                catch { }
            }

            // return a controlled JSON 401 without exposing hidden security artifacts.
            var isIdentityModelDecodeError = context.Exception is Microsoft.IdentityModel.Tokens.SecurityTokenException
                || (context.Exception.Message?.Contains("IDX14102") ?? false);

            if (isIdentityModelDecodeError)
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.ContentType = "application/json";

                var env = context.HttpContext.RequestServices.GetRequiredService<IHostEnvironment>();
                if (env.IsDevelopment())
                {
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_token", details = context.Exception.Message });
                }
                else
                {
                    await context.Response.WriteAsJsonAsync(new { error = "invalid_token", details = "Malformed JWT" });
                }

                return;
            }
                await Task.CompletedTask;
        },

        OnChallenge = context =>
        {
            if (builder.Environment.IsDevelopment() || builder.Configuration.GetValue<bool>("Jwt:DebugShowPII"))
            {
                if (context.Response.HasStarted)
                {
                    return Task.CompletedTask;
                }

                context.HandleResponse();
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.ContentType = "application/json";

                var hasAuthHeader = context.Request.Headers.ContainsKey("Authorization");

                // If the client didn't even send a token, report that clearly.
                if (!hasAuthHeader)
                {
                    return context.Response.WriteAsJsonAsync(new
                    {
                        error = "missing_authorization_header",
                        details = "Send an Authorization header: 'Bearer <token>'"
                    });
                }

                // Otherwise, the header was present but authentication failed.
                var msg = context.AuthenticateFailure?.Message
                          ?? context.ErrorDescription
                          ?? context.Error
                          ?? "unknown";
                var innerMsg = context.AuthenticateFailure?.InnerException?.Message;
                return context.Response.WriteAsJsonAsync(new
                {
                    error = "invalid_token",
                    details = msg,
                    innerDetails = innerMsg,
                    hint = "If you see 'Signature validation failed', the JWT was signed with a different key. Login again to get a fresh token."
                });
            }

            return Task.CompletedTask;
        }
    };

});

// Configure Identity cookie behavior for API endpoints: return 401/403 instead of redirecting to a login page
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Events.OnRedirectToLogin = ctx =>
    {
        if (ctx.Request.Path.StartsWithSegments("/api"))
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        }

        ctx.Response.Redirect(ctx.RedirectUri);
        return Task.CompletedTask;
    };

    options.Events.OnRedirectToAccessDenied = ctx =>
    {
        if (ctx.Request.Path.StartsWithSegments("/api"))
        {
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        }

        ctx.Response.Redirect(ctx.RedirectUri);
        return Task.CompletedTask;
    };
});

// Ensure JWT stays the default authentication scheme (Identity registers cookies as default)
// Use Configure<AuthenticationOptions> so we don't overwrite previously registered handlers (e.g. JwtBearer)
builder.Services.Configure<AuthenticationOptions>(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
});

builder.Services.Configure<ApiBehaviorOptions>(options =>
{
    options.SuppressModelStateInvalidFilter = true;
});

// Require authentication by default (controller/actions can opt-out with [AllowAnonymous])
builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
        .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
        .RequireAuthenticatedUser()
        .Build();

    options.AddPolicy("AdminOnly", policy =>
        policy.AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
              .RequireAuthenticatedUser()
              .RequireRole("Admin"));
});

var app = builder.Build();

app.UseSwaggerUI(options =>
{
    options.SwaggerEndpoint("/openapi/v1.json", "UserManagement");
    options.RoutePrefix = "swagger";
});

app.Use(async (ctx, next) =>
{
    var logger = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("AuthDebug");
    if (ctx.Request.Headers.TryGetValue("Authorization", out var auth))
    {
        var v = auth.ToString();
        var hasBearer = v.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase);
        var token = hasBearer ? v.Substring(7).Trim() : v.Trim();

        logger.LogDebug("[AUTH-DEBUG] hasBearer={HasBearer}, tokenLen={TokenLen}, dots={Dots}, hasQuote={HasQuote}, hasSpace={HasSpace}, hasNewline={HasNewline}",
            hasBearer, token.Length, token.Count(c => c == '.'), token.Contains('"'), token.Contains(' '), token.Contains('\n') || token.Contains('\r'));
    }
    else
    {
        logger.LogDebug("[AUTH-DEBUG] no Authorization header");
    }

    await next();
});

app.UseHttpsRedirection();
app.UseRouting();
app.UseCors("AllowFrontend");
app.UseAuthentication();
app.UseAuthorization();
app.MapOpenApi().AllowAnonymous();
app.MapControllers();

// Seed roles and default admin user
using (var scope = app.Services.CreateScope())
{
    await UserManagement.Data.DbSeeder.SeedRolesAndAdminAsync(scope.ServiceProvider);
}

app.Run();
