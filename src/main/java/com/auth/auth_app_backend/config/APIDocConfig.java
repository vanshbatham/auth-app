package com.auth.auth_app_backend.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @Info(
                title = "Auth System API",
                version = "1.0.0",
                description = "## 🔐 Auth System\n" +
                        "A robust security engine supporting local and social authentication flows.\n\n" +
                        "### Key Features:\n" +
                        "| Feature | Description |\n" +
                        "| :--- | :--- |\n" +
                        "| **Local Auth** | Secure Username/Password login |\n" +
                        "| **OAuth2** | Social login via **Google** and **GitHub** |\n" +
                        "| **Dual Tokens** | Short-lived **Access Tokens** & Long-lived **Refresh Tokens** |\n" +
                        "| **Identity** | Managed user profiles and secure password hashing |\n\n" +
                        "--- \n" +
                        "Developed by **Vansh Batham**",
                summary = "Comprehensive Auth System: Local, OAuth2, and JWT Management",
                contact = @Contact(
                        name = "Vansh Batham",
                        email = "vanshbatham.pro@gmail.com",
                        url = "https://www.linkedin.com/in/vansh-batham16"
                ),
                license = @License(
                        name = "Private License",
                        url = "https://vanshbatham.com/license"
                )
        ),
        servers = {
                @Server(description = "Development Server", url = "http://localhost:8080"),
                @Server(description = "Production Server", url = "https://auth.yourdomain.com")
        },
        security = {
                @SecurityRequirement(name = "Bearer_Token")
        }
)
@SecurityScheme(
        name = "Bearer_Token",
        description = "Provide your **Access Token** to access protected resources. Format: `Bearer <JWT>`",
        type = SecuritySchemeType.HTTP,
        bearerFormat = "JWT",
        scheme = "bearer"
)
public class APIDocConfig {
}