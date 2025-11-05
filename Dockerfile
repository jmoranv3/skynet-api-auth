# ===========================
#   BUILD STAGE
# ===========================
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /app

# Copy everything and restore
COPY . .
RUN dotnet restore

# Publish in Release mode
RUN dotnet publish -c Release -o /app/out

# ===========================
#   RUNTIME STAGE
# ===========================
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS runtime
WORKDIR /app

# Copy published files
COPY --from=build /app/out .

# Expose port (Render will map it automatically)
EXPOSE 8080

# Tell .NET to listen on port 8080 (Render requirement)
ENV ASPNETCORE_URLS=http://+:8080

ENTRYPOINT ["dotnet", "skynet-api-auth.dll"]
