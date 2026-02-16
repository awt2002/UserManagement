using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi.Models;

namespace UserManagement.OpenApi
{
    
    public sealed class BearerSecuritySchemeTransformer : IOpenApiDocumentTransformer
    {
        private readonly IAuthenticationSchemeProvider _schemeProvider;

        public BearerSecuritySchemeTransformer(IAuthenticationSchemeProvider schemeProvider)
        {
            _schemeProvider = schemeProvider;
        }


        public async Task TransformAsync(OpenApiDocument document, OpenApiDocumentTransformerContext context, CancellationToken cancellationToken)
        {
            var schemes = await _schemeProvider.GetAllSchemesAsync();
            if (!schemes.Any(s => s.Name == "Bearer" || s.Name == "JwtBearer"))
                return;

            document.Components ??= new OpenApiComponents();
            document.Components.SecuritySchemes ??= new Dictionary<string, OpenApiSecurityScheme>();

            document.Components.SecuritySchemes["Bearer"] = new OpenApiSecurityScheme
            {
                Type = SecuritySchemeType.Http,
                Scheme = "bearer",
                BearerFormat = "JWT",
                In = ParameterLocation.Header,
                Name = "Authorization",
                Description = "Paste JWT token only (without 'Bearer ')"
            };

            var bearerRef = new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            };

            document.SecurityRequirements ??= new List<OpenApiSecurityRequirement>();
            document.SecurityRequirements.Add(
                new OpenApiSecurityRequirement
                {
                    [bearerRef] = new List<string>()
                }
            );
        }
    }
}