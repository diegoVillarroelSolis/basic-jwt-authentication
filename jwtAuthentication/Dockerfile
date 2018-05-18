FROM microsoft/aspnetcore:2.0 AS base
WORKDIR /app
EXPOSE 80

FROM microsoft/aspnetcore-build:2.0 AS build
WORKDIR /src
COPY jwtAuthentication/jwtAuthentication.csproj jwtAuthentication/
RUN dotnet restore jwtAuthentication/jwtAuthentication.csproj
COPY . .
WORKDIR /src/jwtAuthentication
RUN dotnet build jwtAuthentication.csproj -c Release -o /app

FROM build AS publish
RUN dotnet publish jwtAuthentication.csproj -c Release -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
ENTRYPOINT ["dotnet", "jwtAuthentication.dll"]
