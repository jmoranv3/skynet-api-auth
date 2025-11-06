using Microsoft.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Net.Mail;

namespace SkynetApiAuth;



public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        builder.Services.AddSingleton<SkynetApiAuth.Services.EmailService>();


    var connectionString = Environment.GetEnvironmentVariable("DefaultConnection")
    ?? builder.Configuration.GetConnectionString("DefaultConnection");

        // JSON case sensitivity: enforce exact property names (no case-insensitive binding)
        builder.Services.ConfigureHttpJsonOptions(options =>
        {
            options.SerializerOptions.PropertyNameCaseInsensitive = false;
        });

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowReactApp",
        policy => policy
            .WithOrigins(
                "https://skynet-uasn.onrender.com", // dominio frontend
                "http://localhost:5173"             // opcional para desarrollo
            )
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials()
        );
});
        builder.Configuration
    .SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
    .AddEnvironmentVariables();


        var app = builder.Build();

        app.UseCors("AllowReactApp");


app.MapGet("/test-db", async () =>
{
    var connectionString = Environment.GetEnvironmentVariable("DefaultConnection")
        ?? builder.Configuration.GetConnectionString("DefaultConnection");


Console.WriteLine($"connectionString");
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.BadRequest("❌ No se encontró la cadena de conexión.");

    try
    {
        using var cn = new SqlConnection(connectionString);
        await cn.OpenAsync();

        // Probar SELECT
        var clientes = new List<object>();
        var cmd = new SqlCommand("SELECT TOP 3 id_cliente, nombre, correo FROM TBL_CLIENTES", cn);

        using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            clientes.Add(new
            {
                id_cliente = reader.GetInt32(0),
                nombre = reader.GetString(1),
                correo = reader.IsDBNull(2) ? null : reader.GetString(2)
            });
        }

        return Results.Ok(new
        {
            message = "✅ Conexión a SQL Server exitosa y SELECT realizado",
            encontrados = clientes.Count,
            muestra = clientes
        });
    }
    catch (SqlException ex)
    {
        return Results.Problem($"❌ Error SQL al conectar o consultar:\n{ex.Message}");
    }
    catch (Exception ex)
    {
        return Results.Problem($"❌ Error inesperado:\n{ex.Message}");
    }
});




        // ================== AUTH ==================
               app.MapPost("/auth/login", async (HttpContext context, LoginRequest login) =>
{
    string? clientIp = context.Connection.RemoteIpAddress?.ToString();

    try
    {
        var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

        using var connection = new SqlConnection(connectionString);
       
        await connection.OpenAsync();

        var hashedPassword = HashSHA256(login.clave);



        var query = @"SELECT 
                        U.id_usuario, 
                        U.usuario, 
                        R.descripcion 
                      FROM TBL_USUARIO U
                      INNER JOIN TBL_ROL R ON U.id_rol = R.id_rol
                      WHERE U.usuario = @usuario 
                        AND U.clave = @clave 
                        AND U.activo = 1";

        using var command = new SqlCommand(query, connection);
        command.Parameters.AddWithValue("@usuario", login.usuario);
        command.Parameters.AddWithValue("@clave", hashedPassword);

        using var reader = await command.ExecuteReaderAsync();

        if (await reader.ReadAsync())
        {
            int idUsuario = reader.GetInt32(0);
            string user = reader.GetString(1);
            string rolName = reader.GetString(2);

            string rolCode = rolName switch
            {
                "ADMINISTRADOR" => "ADMIN",
                "SUPERVISOR" => "SUP",
                "TECNICO" => "TEC",
                _ => "UNKNOWN"
            };

            return Results.Ok(new
            {
                message = "Inicio de sesión exitoso",
                id_usuario = idUsuario,
                usuario = user,
                rol = new
                {
                    codigo = rolCode,
                    nombre = rolName
                }
            });
        }

        return Results.Json(new { message = "Usuario o contraseña incorrectos" }, statusCode: 401);
    }
    catch (SqlException ex)
    {
        return Results.Problem($"❌ Error al conectar a SQL Server:\n{ex.Message}\n\n🌐 IP detectada: {clientIp}\n\nAgrega esta IP en el firewall de Azure SQL si es necesario.");
    }
    catch (Exception ex)
    {
        return Results.Problem($"❌ Error inesperado:\n{ex.Message}\n\n🌐 IP detectada: {clientIp}");
    }
});


        app.MapPost("/auth/hash", async (HttpRequest request) =>
        {
            using var reader = new StreamReader(request.Body);
            var texto = await reader.ReadToEndAsync();
            return HashSHA256(texto.Replace("\"", ""));
        });

        // ================== CLIENTES ==================
                    app.MapGet("/api/clientes", async (HttpContext context) =>
                    {
                        string? clientIp = context.Connection.RemoteIpAddress?.ToString();
                        var connectionString = Environment.GetEnvironmentVariable("DefaultConnection")
                            ?? builder.Configuration.GetConnectionString("DefaultConnection");

                        if (string.IsNullOrWhiteSpace(connectionString))
                            return Results.Problem($"❌ No se encontró la cadena de conexión.\n\n🌐 IP: {clientIp}");

                        try
                        {
                            string rol = context.Request.Headers["rol"].ToString().ToUpper();

                            var rolesPermitidos = new[] { "ADMINISTRADOR", "SUPERVISOR", "TECNICO" };

                            if (!rolesPermitidos.Contains(rol))
                                return Results.Unauthorized();

                            using var connection = new SqlConnection(connectionString);
                            await connection.OpenAsync();

                            var query = @"SELECT id_cliente, nombre, nit, direccion, coordenadas, correo, activo, fecha_creacion 
                                        FROM TBL_CLIENTES";

                            var clientes = new List<object>();

                            using var command = new SqlCommand(query, connection);
                            using var reader = await command.ExecuteReaderAsync();

                            while (await reader.ReadAsync())
                            {
                                clientes.Add(new
                                {
                                    id_cliente = reader.GetInt32(0),
                                    nombre = reader.GetString(1),
                                    nit = reader.IsDBNull(2) ? null : reader.GetString(2),
                                    direccion = reader.IsDBNull(3) ? null : reader.GetString(3),
                                    coordenadas = reader.IsDBNull(4) ? null : reader.GetString(4),
                                    correo = reader.IsDBNull(5) ? null : reader.GetString(5),
                                    activo = reader.GetBoolean(6),
                                    fecha_creacion = reader.GetDateTime(7).ToString("yyyy-MM-dd HH:mm:ss")
                                });
                            }

                            return Results.Ok(new { total = clientes.Count, clientes });
                        }
                        catch (SqlException ex)
                        {
                            return Results.Problem($"❌ Error SQL al consultar clientes:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                        }
                        catch (Exception ex)
                        {
                            return Results.Problem($"❌ Error inesperado en /api/clientes:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                        }
                    });


        // ================== DASHBOARD ==================
                app.MapGet("/api/dashboard/visitas/programadas", async (HttpContext context) =>
                {
                    string? clientIp = context.Connection.RemoteIpAddress?.ToString();
                    var connectionString = Environment.GetEnvironmentVariable("DefaultConnection")
                        ?? builder.Configuration.GetConnectionString("DefaultConnection");

                    if (string.IsNullOrWhiteSpace(connectionString))
                        return Results.Problem($"❌ No se encontró la cadena de conexión.\n\n🌐 IP: {clientIp}");

                    try
                    {
                        string rol = context.Request.Headers["rol"].ToString().ToUpper();
                        string idUsuarioStr = context.Request.Headers["id_usuario"];

                        if (!int.TryParse(idUsuarioStr, out int idUsuario))
                            return Results.BadRequest(new { message = "El header 'id_usuario' es requerido y debe ser entero." });

                        using var connection = new SqlConnection(connectionString);
                        await connection.OpenAsync();

                        var query = @"
                        SELECT 
                            V.id_visita,
                            C.nombre AS cliente,
                            U.usuario AS tecnico,
                            V.estado,
                            V.fecha_visita
                        FROM TBL_VISITA V
                        INNER JOIN TBL_CLIENTES C ON V.id_cliente = C.id_cliente
                        INNER JOIN TBL_USUARIO U ON V.id_tecnico = U.id_usuario
                        /**WHERE_CLAUSE**/
                        ORDER BY 
                            CASE V.estado
                                WHEN 'PENDIENTE' THEN 1
                                WHEN 'EN_PROGRESO' THEN 2
                                WHEN 'COMPLETADA' THEN 3
                                WHEN 'CANCELADA' THEN 4
                            END,
                            V.fecha_visita ASC,
                            U.usuario ASC";

                        string whereClause = "WHERE CONVERT(date, V.fecha_visita) = CONVERT(date, GETDATE())";

                        if (rol == "SUP")
                        {
                            whereClause += @" AND V.id_tecnico IN (
                                                SELECT id_tecnico 
                                                FROM TBL_SUPERVISOR_TECNICO 
                                                WHERE id_supervisor = @idUsuario
                                            )";
                        }
                        else if (rol == "TEC")
                        {
                            whereClause += " AND V.id_tecnico = @idUsuario";
                        }

                        query = query.Replace("/**WHERE_CLAUSE**/", whereClause);

                        using var command = new SqlCommand(query, connection);
                        command.Parameters.AddWithValue("@idUsuario", idUsuario);

                        using var reader = await command.ExecuteReaderAsync();
                        var visitas = new List<object>();

                        while (await reader.ReadAsync())
                        {
                            visitas.Add(new
                            {
                                id_visita = reader.GetInt32(0),
                                cliente = reader.GetString(1),
                                tecnico = reader.GetString(2),
                                estado = reader.GetString(3),
                                fecha_visita = reader.GetDateTime(4).ToString("yyyy-MM-dd")
                            });
                        }

                        return Results.Ok(new { total = visitas.Count, visitas });
                    }
                    catch (SqlException ex)
                    {
                        return Results.Problem($"❌ Error SQL:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                    }
                    catch (Exception ex)
                    {
                        return Results.Problem($"❌ Error inesperado:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                    }
                });


                    app.MapGet("/api/dashboard/visitas/completadas", async (HttpContext context) =>
                    {
                        string? clientIp = context.Connection.RemoteIpAddress?.ToString();
                        var connectionString = Environment.GetEnvironmentVariable("DefaultConnection")
                            ?? builder.Configuration.GetConnectionString("DefaultConnection");

                        if (string.IsNullOrWhiteSpace(connectionString))
                            return Results.Problem($"❌ No se encontró la cadena de conexión.\n\n🌐 IP: {clientIp}");

                        try
                        {
                            string rol = context.Request.Headers["rol"].ToString().ToUpper();
                            string idUsuarioStr = context.Request.Headers["id_usuario"];

                            if (!int.TryParse(idUsuarioStr, out int idUsuario))
                                return Results.BadRequest(new { message = "El header 'id_usuario' es requerido y debe ser entero." });

                            using var connection = new SqlConnection(connectionString);
                            await connection.OpenAsync();

                            var query = @"
                            SELECT 
                                V.id_visita,
                                C.nombre AS cliente,
                                U.usuario AS tecnico,
                                V.estado,
                                V.fecha_visita
                            FROM TBL_VISITA V
                            INNER JOIN TBL_CLIENTES C ON V.id_cliente = C.id_cliente
                            INNER JOIN TBL_USUARIO U ON V.id_tecnico = U.id_usuario
                            /**WHERE_CLAUSE**/
                            ORDER BY V.fecha_visita ASC, U.usuario ASC";

                            string whereClause = "WHERE V.estado = 'COMPLETADA' AND CONVERT(date, V.fecha_visita) = CONVERT(date, GETDATE())";

                            if (rol == "SUP")
                            {
                                whereClause += @" AND V.id_tecnico IN (
                                                    SELECT id_tecnico 
                                                    FROM TBL_SUPERVISOR_TECNICO 
                                                    WHERE id_supervisor = @idUsuario
                                                )";
                            }
                            else if (rol == "TEC")
                            {
                                whereClause += " AND V.id_tecnico = @idUsuario";
                            }

                            query = query.Replace("/**WHERE_CLAUSE**/", whereClause);

                            using var command = new SqlCommand(query, connection);
                            command.Parameters.AddWithValue("@idUsuario", idUsuario);

                            using var reader = await command.ExecuteReaderAsync();
                            var visitas = new List<object>();

                            while (await reader.ReadAsync())
                            {
                                visitas.Add(new
                                {
                                    id_visita = reader.GetInt32(0),
                                    cliente = reader.GetString(1),
                                    tecnico = reader.GetString(2),
                                    estado = reader.GetString(3),
                                    fecha_visita = reader.GetDateTime(4).ToString("yyyy-MM-dd")
                                });
                            }

                            return Results.Ok(new { total = visitas.Count, visitas });
                        }
                        catch (SqlException ex)
                        {
                            return Results.Problem($"❌ Error SQL:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                        }
                        catch (Exception ex)
                        {
                            return Results.Problem($"❌ Error inesperado:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                        }
                    });



                    app.MapGet("/api/dashboard/visitas/pendientes", async (HttpContext context) =>
                    {
                        string? clientIp = context.Connection.RemoteIpAddress?.ToString();
                        var connectionString = Environment.GetEnvironmentVariable("DefaultConnection")
                            ?? builder.Configuration.GetConnectionString("DefaultConnection");

                        if (string.IsNullOrWhiteSpace(connectionString))
                            return Results.Problem($"❌ No se encontró la cadena de conexión.\n\n🌐 IP: {clientIp}");

                        try
                        {
                            string rol = context.Request.Headers["rol"].ToString().ToUpper();
                            string idUsuarioStr = context.Request.Headers["id_usuario"];

                            if (!int.TryParse(idUsuarioStr, out int idUsuario))
                                return Results.BadRequest(new { message = "El header 'id_usuario' es requerido y debe ser un número entero." });

                            using var connection = new SqlConnection(connectionString);
                            await connection.OpenAsync();

                            var query = @"
                            SELECT 
                                V.id_visita,
                                C.nombre AS cliente,
                                U.usuario AS tecnico,
                                V.estado,
                                V.fecha_visita
                            FROM TBL_VISITA V
                            INNER JOIN TBL_CLIENTES C ON V.id_cliente = C.id_cliente
                            INNER JOIN TBL_USUARIO U ON V.id_tecnico = U.id_usuario
                            /**WHERE_CLAUSE**/
                            ORDER BY 
                                CASE V.estado
                                    WHEN 'PENDIENTE' THEN 1
                                    WHEN 'EN_PROGRESO' THEN 2
                                    WHEN 'COMPLETADA' THEN 3
                                    WHEN 'CANCELADA' THEN 4
                                END,
                                V.fecha_visita ASC,
                                U.usuario ASC";

                            string whereClause = "WHERE V.estado IN ('PENDIENTE','EN_PROGRESO')";

                            if (rol == "SUP")
                            {
                                whereClause += @" AND V.id_tecnico IN (
                                                    SELECT id_tecnico 
                                                    FROM TBL_SUPERVISOR_TECNICO 
                                                    WHERE id_supervisor = @idUsuario
                                                )";
                            }
                            else if (rol == "TEC")
                            {
                                whereClause += " AND V.id_tecnico = @idUsuario";
                            }

                            query = query.Replace("/**WHERE_CLAUSE**/", whereClause);

                            using var command = new SqlCommand(query, connection);
                            command.Parameters.AddWithValue("@idUsuario", idUsuario);

                            using var reader = await command.ExecuteReaderAsync();
                            var visitas = new List<object>();

                            while (await reader.ReadAsync())
                            {
                                visitas.Add(new
                                {
                                    id_visita = reader.GetInt32(0),
                                    cliente = reader.GetString(1),
                                    tecnico = reader.GetString(2),
                                    estado = reader.GetString(3),
                                    fecha_visita = reader.GetDateTime(4).ToString("yyyy-MM-dd")
                                });
                            }

                            return Results.Ok(new { total = visitas.Count, visitas });
                        }
                        catch (SqlException ex)
                        {
                            return Results.Problem($"❌ Error SQL al obtener visitas pendientes:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                        }
                        catch (Exception ex)
                        {
                            return Results.Problem($"❌ Error inesperado en /api/dashboard/visitas/pendientes:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                        }
                    });



        // ============================= CRUD USUARIOS - SKYNET =============================
        // BASE URL: /api/usuarios
        // ================================================================================

        // Listar usuarios
                app.MapGet("/api/usuarios", async (HttpContext context) =>
                {
                    string? clientIp = context.Connection.RemoteIpAddress?.ToString();
                    var connectionString = Environment.GetEnvironmentVariable("DefaultConnection")
                        ?? builder.Configuration.GetConnectionString("DefaultConnection");

                    if (string.IsNullOrWhiteSpace(connectionString))
                        return Results.Problem($"❌ No se encontró la cadena de conexión.\n\n🌐 IP: {clientIp}");

                    try
                    {
                        using var connection = new SqlConnection(connectionString);
                        await connection.OpenAsync();

                        var query = @"
                            SELECT 
                                IU.id_usuario,
                                IU.nombre,
                                IU.correo,
                                U.usuario,
                                U.id_rol,
                                R.descripcion AS rol,
                                U.activo,
                                ST.id_supervisor_tecnico,
                                ST.id_supervisor,
                                SU.usuario AS supervisor_usuario,
                                SIU.nombre AS supervisor_nombre
                            FROM TBL_INFO_USUARIO IU
                            INNER JOIN TBL_USUARIO U ON U.id_usuario = IU.id_usuario
                            INNER JOIN TBL_ROL R ON R.id_rol = U.id_rol
                            LEFT JOIN TBL_SUPERVISOR_TECNICO ST ON ST.id_tecnico = IU.id_usuario
                            LEFT JOIN TBL_USUARIO SU ON SU.id_usuario = ST.id_supervisor
                            LEFT JOIN TBL_INFO_USUARIO SIU ON SIU.id_usuario = SU.id_usuario
                            ORDER BY IU.id_usuario DESC";

                        var usuarios = new List<object>();

                        using var command = new SqlCommand(query, connection);
                        using var reader = await command.ExecuteReaderAsync();

                        while (await reader.ReadAsync())
                        {
                            usuarios.Add(new
                            {
                                id_usuario = reader.GetInt32(0),
                                nombre = reader.GetString(1),
                                correo = reader.GetString(2),
                                usuario = reader.GetString(3),
                                id_rol = reader.GetInt32(4),
                                rol = reader.GetString(5),
                                activo = reader.GetBoolean(6),
                                id_supervisor_tecnico = reader.IsDBNull(7) ? (int?)null : reader.GetInt32(7),
                                id_supervisor = reader.IsDBNull(8) ? (int?)null : reader.GetInt32(8),
                                supervisor_usuario = reader.IsDBNull(9) ? null : reader.GetString(9),
                                supervisor_nombre = reader.IsDBNull(10) ? null : reader.GetString(10)
                            });
                        }

                        return Results.Ok(new { total = usuarios.Count, usuarios });
                    }
                    catch (SqlException ex)
                    {
                        return Results.Problem($"❌ Error SQL al obtener usuarios:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                    }
                    catch (Exception ex)
                    {
                        return Results.Problem($"❌ Error inesperado en /api/usuarios:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                    }
                });


        // Listar supervisores
                app.MapGet("/api/usuarios/supervisores", async (HttpContext context) =>
                {
                    string? clientIp = context.Connection.RemoteIpAddress?.ToString();
                    var connectionString = Environment.GetEnvironmentVariable("DefaultConnection")
                        ?? builder.Configuration.GetConnectionString("DefaultConnection");

                    if (string.IsNullOrWhiteSpace(connectionString))
                        return Results.Problem($"❌ No se encontró la cadena de conexión.\n\n🌐 IP: {clientIp}");

                    try
                    {
                        using var connection = new SqlConnection(connectionString);
                        await connection.OpenAsync();

                        var query = @"
                            SELECT IU.id_usuario, IU.nombre, IU.correo, U.usuario, U.activo
                            FROM TBL_INFO_USUARIO IU
                            INNER JOIN TBL_USUARIO U ON U.id_usuario = IU.id_usuario
                            INNER JOIN TBL_ROL R ON R.id_rol = U.id_rol
                            WHERE R.descripcion = 'SUPERVISOR'
                            ORDER BY IU.nombre";

                        var supervisores = new List<object>();

                        using var command = new SqlCommand(query, connection);
                        using var reader = await command.ExecuteReaderAsync();

                        while (await reader.ReadAsync())
                        {
                            supervisores.Add(new
                            {
                                id_usuario = reader.GetInt32(0),
                                nombre = reader.GetString(1),
                                correo = reader.GetString(2),
                                usuario = reader.GetString(3),
                                activo = reader.GetBoolean(4)
                            });
                        }

                        return Results.Ok(new { total = supervisores.Count, supervisores });
                    }
                    catch (SqlException ex)
                    {
                        return Results.Problem($"❌ Error SQL al obtener supervisores:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                    }
                    catch (Exception ex)
                    {
                        return Results.Problem($"❌ Error inesperado en /api/usuarios/supervisores:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                    }
                });

        // Listar técnicos
                app.MapGet("/api/usuarios/tecnicos", async (HttpContext context) =>
                {
                    string? clientIp = context.Connection.RemoteIpAddress?.ToString();
                    var connectionString = Environment.GetEnvironmentVariable("DefaultConnection")
                        ?? builder.Configuration.GetConnectionString("DefaultConnection");

                    if (string.IsNullOrWhiteSpace(connectionString))
                        return Results.Problem($"❌ No se encontró la cadena de conexión.\n\n🌐 IP: {clientIp}");

                    try
                    {
                        using var connection = new SqlConnection(connectionString);
                        await connection.OpenAsync();

                        var query = @"
                            SELECT IU.id_usuario, IU.nombre, IU.correo, U.usuario, U.activo
                            FROM TBL_INFO_USUARIO IU
                            INNER JOIN TBL_USUARIO U ON U.id_usuario = IU.id_usuario
                            INNER JOIN TBL_ROL R ON R.id_rol = U.id_rol
                            WHERE R.descripcion = 'TECNICO'
                            ORDER BY IU.nombre";

                        var tecnicos = new List<object>();

                        using var command = new SqlCommand(query, connection);
                        using var reader = await command.ExecuteReaderAsync();

                        while (await reader.ReadAsync())
                        {
                            tecnicos.Add(new
                            {
                                id_usuario = reader.GetInt32(0),
                                nombre = reader.GetString(1),
                                correo = reader.GetString(2),
                                usuario = reader.GetString(3),
                                activo = reader.GetBoolean(4)
                            });
                        }

                        return Results.Ok(new { total = tecnicos.Count, tecnicos });
                    }
                    catch (SqlException ex)
                    {
                        return Results.Problem($"❌ Error SQL al obtener técnicos:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                    }
                    catch (Exception ex)
                    {
                        return Results.Problem($"❌ Error inesperado en /api/usuarios/tecnicos:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                    }
                });


        // Crear usuario
                app.MapPost("/api/usuarios", async (HttpContext context, UserCreateDto dto) =>
                {
                    string? clientIp = context.Connection.RemoteIpAddress?.ToString();
                    var connectionString = Environment.GetEnvironmentVariable("DefaultConnection")
                        ?? builder.Configuration.GetConnectionString("DefaultConnection");

                    if (string.IsNullOrWhiteSpace(connectionString))
                        return Results.Problem($"❌ No se encontró la cadena de conexión.\n\n🌐 IP: {clientIp}");

                    if (dto is null)
                        return Results.BadRequest(new { message = "Datos inválidos" });

                    var rolUpper = (dto.rol ?? "").ToUpper();
                    if (rolUpper == "TECNICO" && dto.id_supervisor is null)
                        return Results.BadRequest(new { message = "Debe seleccionar un supervisor para el técnico." });

                    SqlTransaction? tx = null;
                    int newId = 0;

                    try
                    {
                        using var connection = new SqlConnection(connectionString);
                        await connection.OpenAsync();
                        tx = connection.BeginTransaction();

                        // Validar usuario duplicado
                        using (var checkCmd = new SqlCommand("SELECT COUNT(*) FROM TBL_USUARIO WHERE usuario = @usuario", connection, tx))
                        {
                            checkCmd.Parameters.AddWithValue("@usuario", dto.usuario);
                            int exists = (int)await checkCmd.ExecuteScalarAsync();
                            if (exists > 0)
                            {
                                tx.Rollback();
                                return Results.BadRequest(new { message = "El usuario ya existe, elija otro." });
                            }
                        }

                        var hashedPassword = HashSHA256(dto.clave);

                        // 1) Insertar TBL_INFO_USUARIO
                        using (var cmdInfo = new SqlCommand(
                            "INSERT INTO TBL_INFO_USUARIO (nombre, correo) OUTPUT INSERTED.id_usuario VALUES (@nombre, @correo)", connection, tx))
                        {
                            cmdInfo.Parameters.AddWithValue("@nombre", dto.nombre);
                            cmdInfo.Parameters.AddWithValue("@correo", dto.correo);
                            newId = (int)await cmdInfo.ExecuteScalarAsync();
                        }

                        // 2) Insertar TBL_USUARIO
                        using (var cmdUser = new SqlCommand(
                            "INSERT INTO TBL_USUARIO (id_usuario, usuario, clave, id_rol) VALUES (@id_usuario, @usuario, @clave, @id_rol)", connection, tx))
                        {
                            cmdUser.Parameters.AddWithValue("@id_usuario", newId);
                            cmdUser.Parameters.AddWithValue("@usuario", dto.usuario);
                            cmdUser.Parameters.AddWithValue("@clave", hashedPassword);
                            cmdUser.Parameters.AddWithValue("@id_rol", dto.id_rol);
                            await cmdUser.ExecuteNonQueryAsync();
                        }

                        // 3) Si es técnico, asignar supervisor
                        if (rolUpper == "TECNICO")
                        {
                            using var cmdSup = new SqlCommand(
                                "INSERT INTO TBL_SUPERVISOR_TECNICO (id_supervisor, id_tecnico) VALUES (@id_sup, @id_tec)", connection, tx);
                            cmdSup.Parameters.AddWithValue("@id_sup", dto.id_supervisor);
                            cmdSup.Parameters.AddWithValue("@id_tec", newId);
                            await cmdSup.ExecuteNonQueryAsync();
                        }

                        await tx.CommitAsync();
                        tx = null; // para no intentar rollback en catch

                        // Enviar correo (no afecta la DB si falla)
                        try
                        {
                            var emailService = app.Services.GetService<SkynetApiAuth.Services.EmailService>();
                            emailService?.SendUserCredentials(dto.correo, dto.usuario, dto.clave, dto.rol, dto.nombre);
                        }
                        catch (Exception exMail)
                        {
                            Console.WriteLine("⚠️ Error al enviar correo (no afecta creación): " + exMail.Message);
                        }

                        return Results.Ok(new { message = "Usuario creado exitosamente", id_usuario = newId });
                    }
                    catch (SqlException ex)
                    {
                        if (tx is not null) { try { tx.Rollback(); } catch { } }
                        return Results.Problem($"❌ Error SQL al crear usuario:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                    }
                    catch (Exception ex)
                    {
                        if (tx is not null) { try { tx.Rollback(); } catch { } }
                        return Results.Problem($"❌ Error inesperado en creación de usuario:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                    }
                });


        // Actualizar usuario
                    app.MapPut("/api/usuarios/{id:int}", async (HttpContext context, int id, UserUpdateDto dto) =>
                    {
                        string? clientIp = context.Connection.RemoteIpAddress?.ToString();
                        var connectionString = Environment.GetEnvironmentVariable("DefaultConnection")
                            ?? builder.Configuration.GetConnectionString("DefaultConnection");

                        if (string.IsNullOrWhiteSpace(connectionString))
                            return Results.Problem($"❌ No se encontró la cadena de conexión.\n\n🌐 IP: {clientIp}");

                        if (dto is null)
                            return Results.BadRequest(new { message = "Datos inválidos" });

                        var rolUpper = (dto.rol ?? "").ToUpper();
                        if (rolUpper == "TECNICO" && dto.id_supervisor is null)
                            return Results.BadRequest(new { message = "Debe seleccionar un supervisor para el técnico." });

                        SqlTransaction? tx = null;

                        try
                        {
                            using var connection = new SqlConnection(connectionString);
                            await connection.OpenAsync();
                            tx = connection.BeginTransaction();

                            // Validar existencia del usuario
                            using (var existsCmd = new SqlCommand("SELECT COUNT(*) FROM TBL_USUARIO WHERE id_usuario = @id", connection, tx))
                            {
                                existsCmd.Parameters.AddWithValue("@id", id);
                                if ((int)await existsCmd.ExecuteScalarAsync() == 0)
                                {
                                    tx.Rollback();
                                    return Results.NotFound(new { message = "Usuario no encontrado" });
                                }
                            }

                            // Validación: Usuario duplicado (excepto él mismo)
                            using (var checkCmd = new SqlCommand("SELECT COUNT(*) FROM TBL_USUARIO WHERE usuario = @usuario AND id_usuario <> @id", connection, tx))
                            {
                                checkCmd.Parameters.AddWithValue("@usuario", dto.usuario);
                                checkCmd.Parameters.AddWithValue("@id", id);
                                int exists = (int)await checkCmd.ExecuteScalarAsync();
                                if (exists > 0)
                                {
                                    tx.Rollback();
                                    return Results.BadRequest(new { message = "El usuario ya está en uso, elija otro." });
                                }
                            }

                            // Actualizar TBL_INFO_USUARIO
                            using (var cmdInfo = new SqlCommand(
                                "UPDATE TBL_INFO_USUARIO SET nombre=@nombre, correo=@correo WHERE id_usuario=@id", connection, tx))
                            {
                                cmdInfo.Parameters.AddWithValue("@nombre", dto.nombre);
                                cmdInfo.Parameters.AddWithValue("@correo", dto.correo);
                                cmdInfo.Parameters.AddWithValue("@id", id);
                                await cmdInfo.ExecuteNonQueryAsync();
                            }

                            // Actualizar TBL_USUARIO (sin clave aún)
                            using (var cmdUser = new SqlCommand(
                                "UPDATE TBL_USUARIO SET usuario=@usuario, id_rol=@id_rol, activo=@activo WHERE id_usuario=@id", connection, tx))
                            {
                                cmdUser.Parameters.AddWithValue("@usuario", dto.usuario);
                                cmdUser.Parameters.AddWithValue("@id_rol", dto.id_rol);
                                cmdUser.Parameters.AddWithValue("@activo", dto.activo);
                                cmdUser.Parameters.AddWithValue("@id", id);
                                await cmdUser.ExecuteNonQueryAsync();
                            }

                            // Si envió clave, actualizar
                            if (!string.IsNullOrWhiteSpace(dto.clave))
                            {
                                var hashedPass = HashSHA256(dto.clave);
                                using var cmdPass = new SqlCommand("UPDATE TBL_USUARIO SET clave=@clave WHERE id_usuario=@id", connection, tx);
                                cmdPass.Parameters.AddWithValue("@clave", hashedPass);
                                cmdPass.Parameters.AddWithValue("@id", id);
                                await cmdPass.ExecuteNonQueryAsync();
                            }

                            // Relación supervisor-técnico
                            if (rolUpper == "TECNICO")
                            {
                                // Upsert de relación
                                int count;
                                using (var checkRel = new SqlCommand("SELECT COUNT(*) FROM TBL_SUPERVISOR_TECNICO WHERE id_tecnico=@id", connection, tx))
                                {
                                    checkRel.Parameters.AddWithValue("@id", id);
                                    count = (int)await checkRel.ExecuteScalarAsync();
                                }

                                if (count > 0)
                                {
                                    using var updateRel = new SqlCommand(
                                        "UPDATE TBL_SUPERVISOR_TECNICO SET id_supervisor=@sup WHERE id_tecnico=@id", connection, tx);
                                    updateRel.Parameters.AddWithValue("@sup", dto.id_supervisor);
                                    updateRel.Parameters.AddWithValue("@id", id);
                                    await updateRel.ExecuteNonQueryAsync();
                                }
                                else
                                {
                                    using var insertRel = new SqlCommand(
                                        "INSERT INTO TBL_SUPERVISOR_TECNICO (id_supervisor, id_tecnico) VALUES (@sup, @id)", connection, tx);
                                    insertRel.Parameters.AddWithValue("@sup", dto.id_supervisor);
                                    insertRel.Parameters.AddWithValue("@id", id);
                                    await insertRel.ExecuteNonQueryAsync();
                                }
                            }
                            else
                            {
                                // Si ya no es técnico, elimina cualquier relación previa
                                using var delRel = new SqlCommand("DELETE FROM TBL_SUPERVISOR_TECNICO WHERE id_tecnico=@id", connection, tx);
                                delRel.Parameters.AddWithValue("@id", id);
                                await delRel.ExecuteNonQueryAsync();
                            }

                            await tx.CommitAsync();
                            tx = null;

                            return Results.Ok(new { message = "Usuario actualizado correctamente" });
                        }
                        catch (SqlException ex)
                        {
                            if (tx is not null) { try { tx.Rollback(); } catch { } }
                            return Results.Problem($"❌ Error SQL al actualizar usuario:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                        }
                        catch (Exception ex)
                        {
                            if (tx is not null) { try { tx.Rollback(); } catch { } }
                            return Results.Problem($"❌ Error inesperado al actualizar usuario:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                        }
                    });

        // Inactivar usuario (baja lógica)
                app.MapDelete("/api/usuarios/{id:int}", async (HttpContext context, int id) =>
                {
                    string? clientIp = context.Connection.RemoteIpAddress?.ToString();
                    var connectionString = Environment.GetEnvironmentVariable("DefaultConnection")
                        ?? builder.Configuration.GetConnectionString("DefaultConnection");

                    if (string.IsNullOrWhiteSpace(connectionString))
                        return Results.Problem($"❌ No se encontró la cadena de conexión.\n\n🌐 IP: {clientIp}");

                    try
                    {
                        using var connection = new SqlConnection(connectionString);
                        await connection.OpenAsync();

                        // Verificar estado actual antes de actualizar
                        using (var checkCmd = new SqlCommand("SELECT activo FROM TBL_USUARIO WHERE id_usuario = @id", connection))
                        {
                            checkCmd.Parameters.AddWithValue("@id", id);
                            var result = await checkCmd.ExecuteScalarAsync();

                            if (result is null)
                                return Results.NotFound(new { message = "Usuario no encontrado" });

                            bool activoActual = Convert.ToBoolean(result);

                            if (!activoActual)
                                return Results.Ok(new { message = "El usuario ya estaba inactivo" });
                        }

                        using (var cmd = new SqlCommand("UPDATE TBL_USUARIO SET activo = 0 WHERE id_usuario = @id", connection))
                        {
                            cmd.Parameters.AddWithValue("@id", id);
                            await cmd.ExecuteNonQueryAsync();
                        }

                        return Results.Ok(new { message = "✅ Usuario inactivado correctamente" });
                    }
                    catch (SqlException ex)
                    {
                        return Results.Problem($"❌ Error SQL al inactivar usuario:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                    }
                    catch (Exception ex)
                    {
                        return Results.Problem($"❌ Error inesperado al inactivar usuario:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                    }
                });


        // POST /api/clientes (ADMINISTRADOR, SUPERVISOR)
                app.MapPost("/api/clientes", async (HttpContext context) =>
                {
                    string? clientIp = context.Connection.RemoteIpAddress?.ToString();
                    var connectionString = Environment.GetEnvironmentVariable("DefaultConnection")
                        ?? builder.Configuration.GetConnectionString("DefaultConnection");

                    if (string.IsNullOrWhiteSpace(connectionString))
                        return Results.Problem($"❌ No se encontró la cadena de conexión.\n\n🌐 IP: {clientIp}");

                    try
                    {
                        string rol = context.Request.Headers["rol"].ToString().ToUpper();
                        if (!(rol == "ADMINISTRADOR" || rol == "SUPERVISOR"))
                            return Results.Unauthorized();

                        var dto = await context.Request.ReadFromJsonAsync<ClienteDto>();
                        if (dto == null || string.IsNullOrWhiteSpace(dto.nombre))
                            return Results.BadRequest(new { message = "El nombre del cliente es requerido" });

                        using var con = new SqlConnection(connectionString);
                        await con.OpenAsync();

                        var cmd = new SqlCommand(@"
                            INSERT INTO TBL_CLIENTES (nombre, nit, direccion, coordenadas, correo)
                            VALUES (@n,@nit,@dir,@coord,@mail);
                            SELECT SCOPE_IDENTITY();", con);

                        cmd.Parameters.AddWithValue("@n", dto.nombre);
                        cmd.Parameters.AddWithValue("@nit", (object?)dto.nit ?? DBNull.Value);
                        cmd.Parameters.AddWithValue("@dir", (object?)dto.direccion ?? DBNull.Value);
                        cmd.Parameters.AddWithValue("@coord", (object?)dto.coordenadas ?? DBNull.Value);
                        cmd.Parameters.AddWithValue("@mail", (object?)dto.correo ?? DBNull.Value);

                        int id = Convert.ToInt32(await cmd.ExecuteScalarAsync());

                        return Results.Ok(new { message = "✅ Cliente creado exitosamente", id_cliente = id });
                    }
                    catch (SqlException ex)
                    {
                        return Results.Problem($"❌ Error SQL al crear cliente:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                    }
                    catch (Exception ex)
                    {
                        return Results.Problem($"❌ Error inesperado al crear cliente:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                    }
                });


        // PUT /api/clientes/{id} (ADMINISTRADOR, SUPERVISOR)
                    app.MapPut("/api/clientes/{id:int}", async (HttpContext context, int id) =>
                    {
                        string? clientIp = context.Connection.RemoteIpAddress?.ToString();
                        var connectionString = Environment.GetEnvironmentVariable("DefaultConnection")
                            ?? builder.Configuration.GetConnectionString("DefaultConnection");

                        if (string.IsNullOrWhiteSpace(connectionString))
                            return Results.Problem($"❌ No se encontró la cadena de conexión.\n\n🌐 IP: {clientIp}");

                        try
                        {
                            var rol = context.Request.Headers["rol"].ToString().ToUpper();
                            if (!(rol == "ADMINISTRADOR" || rol == "SUPERVISOR"))
                                return Results.Unauthorized();

                            var dto = await context.Request.ReadFromJsonAsync<ClienteUpdateDto>();
                            if (dto == null || string.IsNullOrWhiteSpace(dto.nombre))
                                return Results.BadRequest(new { message = "Datos inválidos o incompletos" });

                            using var con = new SqlConnection(connectionString);
                            await con.OpenAsync();

                            // Verificar existencia
                            using (var check = new SqlCommand("SELECT COUNT(*) FROM TBL_CLIENTES WHERE id_cliente=@id", con))
                            {
                                check.Parameters.AddWithValue("@id", id);
                                if ((int)await check.ExecuteScalarAsync() == 0)
                                    return Results.NotFound(new { message = "Cliente no encontrado" });
                            }

                            var cmd = new SqlCommand(@"
                                UPDATE TBL_CLIENTES
                                SET nombre=@n, nit=@nit, direccion=@dir, coordenadas=@coord, correo=@mail, activo=@act
                                WHERE id_cliente=@id", con);

                            cmd.Parameters.AddWithValue("@id", id);
                            cmd.Parameters.AddWithValue("@n", dto.nombre);
                            cmd.Parameters.AddWithValue("@nit", (object?)dto.nit ?? DBNull.Value);
                            cmd.Parameters.AddWithValue("@dir", (object?)dto.direccion ?? DBNull.Value);
                            cmd.Parameters.AddWithValue("@coord", (object?)dto.coordenadas ?? DBNull.Value);
                            cmd.Parameters.AddWithValue("@mail", (object?)dto.correo ?? DBNull.Value);
                            cmd.Parameters.AddWithValue("@act", dto.activo);

                            await cmd.ExecuteNonQueryAsync();

                            return Results.Ok(new { message = "✅ Cliente actualizado correctamente" });
                        }
                        catch (SqlException ex)
                        {
                            return Results.Problem($"❌ Error SQL al actualizar cliente:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                        }
                        catch (Exception ex)
                        {
                            return Results.Problem($"❌ Error inesperado al actualizar cliente:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                        }
                    });


        // DELETE /api/clientes/{id} (ADMINISTRADOR) → inactivar
                    app.MapDelete("/api/clientes/{id:int}", async (HttpContext context, int id) =>
                    {
                        string? clientIp = context.Connection.RemoteIpAddress?.ToString();
                        var connectionString = Environment.GetEnvironmentVariable("DefaultConnection")
                            ?? builder.Configuration.GetConnectionString("DefaultConnection");

                        if (string.IsNullOrWhiteSpace(connectionString))
                            return Results.Problem($"❌ No se encontró la cadena de conexión.\n\n🌐 IP: {clientIp}");

                        try
                        {
                            var rol = context.Request.Headers["rol"].ToString().ToUpper();
                            if (rol != "ADMINISTRADOR")
                                return Results.Unauthorized();

                            using var con = new SqlConnection(connectionString);
                            await con.OpenAsync();

                            // Verificar estado actual
                            using (var check = new SqlCommand("SELECT activo FROM TBL_CLIENTES WHERE id_cliente=@id", con))
                            {
                                check.Parameters.AddWithValue("@id", id);
                                var result = await check.ExecuteScalarAsync();

                                if (result is null)
                                    return Results.NotFound(new { message = "Cliente no encontrado" });

                                bool activoActual = Convert.ToBoolean(result);

                                if (!activoActual)
                                    return Results.Ok(new { message = "El cliente ya estaba inactivo" });
                            }

                            using (var cmd = new SqlCommand("UPDATE TBL_CLIENTES SET activo=0 WHERE id_cliente=@id", con))
                            {
                                cmd.Parameters.AddWithValue("@id", id);
                                await cmd.ExecuteNonQueryAsync();
                            }

                            return Results.Ok(new { message = "✅ Cliente inactivado correctamente" });
                        }
                        catch (SqlException ex)
                        {
                            return Results.Problem($"❌ Error SQL al inactivar cliente:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                        }
                        catch (Exception ex)
                        {
                            return Results.Problem($"❌ Error inesperado al inactivar cliente:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                        }
                    });



                        app.MapGet("/api/visitas/form-data", async (HttpContext context) =>
                        {
                            string? clientIp = context.Connection.RemoteIpAddress?.ToString();

                            var connectionString = Environment.GetEnvironmentVariable("DefaultConnection") 
                                ?? builder.Configuration.GetConnectionString("DefaultConnection");

                            if (string.IsNullOrWhiteSpace(connectionString))
                                return Results.Problem($"❌ No se encontró la cadena de conexión.\n\n🌐 IP: {clientIp}");

                            try
                            {
                                string? supIdStr = context.Request.Query["supervisorId"];
                                int? supId = null;

                                if (!string.IsNullOrWhiteSpace(supIdStr) && int.TryParse(supIdStr, out var parsedSupId))
                                    supId = parsedSupId;

                                using var cn = new SqlConnection(connectionString);
                                await cn.OpenAsync();

                                // ============ CLIENTES ============
                                var clientes = new List<object>();
                                using (var cmd = new SqlCommand(@"
                                    SELECT id_cliente, nombre, direccion, coordenadas 
                                    FROM TBL_CLIENTES 
                                    WHERE activo = 1 
                                    ORDER BY nombre", cn))
                                using (var rd = await cmd.ExecuteReaderAsync())
                                {
                                    while (await rd.ReadAsync())
                                    {
                                        clientes.Add(new
                                        {
                                            id_cliente = rd.GetInt32(0),
                                            nombre = rd.GetString(1),
                                            direccion = rd.IsDBNull(2) ? null : rd.GetString(2),
                                            coordenadas = rd.IsDBNull(3) ? null : rd.GetString(3)
                                        });
                                    }
                                }

                                // ============ SUPERVISORES ============
                                var supervisores = new List<object>();
                                using (var cmd = new SqlCommand(@"
                                    SELECT IU.id_usuario, U.usuario, IU.nombre
                                    FROM TBL_INFO_USUARIO IU
                                    INNER JOIN TBL_USUARIO U ON U.id_usuario = IU.id_usuario
                                    INNER JOIN TBL_ROL R ON R.id_rol = U.id_rol
                                    WHERE R.descripcion = 'SUPERVISOR' AND U.activo = 1
                                    ORDER BY IU.nombre", cn))
                                using (var rd = await cmd.ExecuteReaderAsync())
                                {
                                    while (await rd.ReadAsync())
                                    {
                                        supervisores.Add(new
                                        {
                                            id_usuario = rd.GetInt32(0),
                                            usuario = rd.GetString(1),
                                            nombre = rd.GetString(2)
                                        });
                                    }
                                }

                                // ============ TÉCNICOS (FILTRADOS OPCIONALMENTE POR SUPERVISOR) ============
                                var tecnicos = new List<object>();
                                string qTec = @"
                                    SELECT IU.id_usuario, U.usuario, IU.nombre
                                    FROM TBL_INFO_USUARIO IU
                                    INNER JOIN TBL_USUARIO U ON U.id_usuario = IU.id_usuario
                                    INNER JOIN TBL_ROL R ON R.id_rol = U.id_rol
                                    WHERE R.descripcion = 'TECNICO' AND U.activo = 1
                                    ORDER BY IU.nombre";

                                if (supId.HasValue)
                                {
                                    qTec = @"
                                        SELECT IU.id_usuario, U.usuario, IU.nombre
                                        FROM TBL_SUPERVISOR_TECNICO ST
                                        INNER JOIN TBL_USUARIO U ON U.id_usuario = ST.id_tecnico
                                        INNER JOIN TBL_INFO_USUARIO IU ON IU.id_usuario = U.id_usuario
                                        WHERE ST.id_supervisor = @idSup AND U.activo = 1
                                        ORDER BY IU.nombre";
                                }

                                using (var cmd = new SqlCommand(qTec, cn))
                                {
                                    if (supId.HasValue) cmd.Parameters.AddWithValue("@idSup", supId.Value);

                                    using var rd = await cmd.ExecuteReaderAsync();
                                    while (await rd.ReadAsync())
                                    {
                                        tecnicos.Add(new
                                        {
                                            id_usuario = rd.GetInt32(0),
                                            usuario = rd.GetString(1),
                                            nombre = rd.GetString(2)
                                        });
                                    }
                                }

                                return Results.Ok(new
                                {
                                    totalClientes = clientes.Count,
                                    totalSupervisores = supervisores.Count,
                                    totalTecnicos = tecnicos.Count,
                                    clientes,
                                    supervisores,
                                    tecnicos
                                });
                            }
                            catch (SqlException ex)
                            {
                                return Results.Problem($"❌ Error SQL en form-data:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                            }
                            catch (Exception ex)
                            {
                                return Results.Problem($"❌ Error inesperado en form-data:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                            }
                        });




                    app.MapGet("/api/visitas", async (HttpContext context) =>
                    {
                        string? clientIp = context.Connection.RemoteIpAddress?.ToString();

                        var connectionString = Environment.GetEnvironmentVariable("DefaultConnection")
                            ?? builder.Configuration.GetConnectionString("DefaultConnection");

                        if (string.IsNullOrWhiteSpace(connectionString))
                            return Results.Problem($"❌ No se encontró la cadena de conexión.\n\n🌐 IP: {clientIp}");

                        try
                        {
                            // Obtener y validar Headers
                            string rol = context.Request.Headers["rol"].ToString().ToUpper();
                            string idUsuarioRaw = context.Request.Headers["id_usuario"].ToString();

                            if (string.IsNullOrWhiteSpace(rol) || string.IsNullOrWhiteSpace(idUsuarioRaw))
                                return Results.BadRequest(new { message = "Headers requeridos: rol, id_usuario" });

                            if (!int.TryParse(idUsuarioRaw, out int idUsuario))
                                return Results.BadRequest(new { message = "id_usuario debe ser un número válido" });

                            var visitas = new List<object>();

                            using var cn = new SqlConnection(connectionString);
                            await cn.OpenAsync();

                            var query = @"
                                SELECT 
                                V.id_visita,
                                V.id_cliente,
                                V.id_supervisor,
                                V.id_tecnico,
                                V.fecha_creacion,
                                V.fecha_visita,
                                V.estado,
                                V.coordenadas_planificadas,
                                C.nombre AS cliente,
                                C.direccion AS cliente_direccion,
                                C.coordenadas AS cliente_coordenadas,
                                SU.usuario AS supervisor,
                                TU.usuario AS tecnico
                                FROM TBL_VISITA V
                                INNER JOIN TBL_CLIENTES C ON C.id_cliente = V.id_cliente
                                INNER INNER JOIN TBL_USUARIO SU ON SU.id_usuario = V.id_supervisor
                                INNER JOIN TBL_USUARIO TU ON TU.id_usuario = V.id_tecnico
                                /**WHERE_CLAUSE**/
                                ORDER BY V.id_visita DESC";

                            string where = rol switch
                            {
                                "SUP" => @"
                                    WHERE V.id_tecnico IN (
                                        SELECT id_tecnico 
                                        FROM TBL_SUPERVISOR_TECNICO 
                                        WHERE id_supervisor = @idUsuario
                                    )",
                                "TEC" => "WHERE V.id_tecnico = @idUsuario",
                                _ => "" // ADMIN u otro → ve todo
                            };

                            query = query.Replace("/**WHERE_CLAUSE**/", where);

                            using var cmd = new SqlCommand(query, cn);
                            cmd.Parameters.AddWithValue("@idUsuario", idUsuario);

                            using var rd = await cmd.ExecuteReaderAsync();
                            while (await rd.ReadAsync())
                            {
                                visitas.Add(new
                                {
                                    id_visita = rd.GetInt32(0),
                                    id_cliente = rd.GetInt32(1),
                                    id_supervisor = rd.GetInt32(2),
                                    id_tecnico = rd.GetInt32(3),
                                    fecha_creacion = rd.GetDateTime(4).ToString("yyyy-MM-dd HH:mm:ss"),
                                    fecha_visita = rd.GetDateTime(5).ToString("yyyy-MM-dd"),
                                    estado = rd.GetString(6),
                                    coordenadas_planificadas = rd.IsDBNull(7) ? null : rd.GetString(7),
                                    cliente = rd.GetString(8),
                                    cliente_direccion = rd.IsDBNull(9) ? null : rd.GetString(9),
                                    cliente_coordenadas = rd.IsDBNull(10) ? null : rd.GetString(10),
                                    supervisor = rd.GetString(11),
                                    tecnico = rd.GetString(12)
                                });
                            }

                            return Results.Ok(new
                            {
                                total = visitas.Count,
                                visitas
                            });
                        }
                        catch (SqlException ex)
                        {
                            return Results.Problem($"❌ Error SQL en /api/visitas:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                        }
                        catch (Exception ex)
                        {
                            return Results.Problem($"❌ Error inesperado en /api/visitas:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                        }
                    });



                        app.MapPost("/api/visitas", async (HttpContext context, VisitaCreateDto dto) =>
                        {
                            string? clientIp = context.Connection.RemoteIpAddress?.ToString();

                            var connectionString = Environment.GetEnvironmentVariable("DefaultConnection")
                                ?? builder.Configuration.GetConnectionString("DefaultConnection");

                            if (string.IsNullOrWhiteSpace(connectionString))
                                return Results.Problem($"❌ No se encontró la cadena de conexión.\n\n🌐 IP: {clientIp}");

                            try
                            {
                                // Validar DTO
                                if (dto == null)
                                    return Results.BadRequest(new { message = "Datos inválidos" });

                                if (dto.id_cliente <= 0 || dto.id_supervisor <= 0 || dto.id_tecnico <= 0)
                                    return Results.BadRequest(new { message = "Cliente, Supervisor y Técnico son obligatorios" });

                                if (!DateTime.TryParse(dto.fecha_visita, out var fechaVisitaParsed))
                                    return Results.BadRequest(new { message = "La fecha_visita no tiene un formato válido (yyyy-MM-dd)" });

                                using var cn = new SqlConnection(connectionString);
                                await cn.OpenAsync();

                                // 🔹 Insertar visita
                                var insertQuery = @"
                                    INSERT INTO TBL_VISITA (id_cliente, id_supervisor, id_tecnico, coordenadas_planificadas, fecha_visita)
                                    OUTPUT INSERTED.id_visita
                                    VALUES (@cli, @sup, @tec, @coord, @fecha)";
                                
                                int idVisita;
                                using (var cmd = new SqlCommand(insertQuery, cn))
                                {
                                    cmd.Parameters.AddWithValue("@cli", dto.id_cliente);
                                    cmd.Parameters.AddWithValue("@sup", dto.id_supervisor);
                                    cmd.Parameters.AddWithValue("@tec", dto.id_tecnico);
                                    cmd.Parameters.AddWithValue("@coord", (object?)dto.coordenadas_planificadas ?? DBNull.Value);
                                    cmd.Parameters.AddWithValue("@fecha", fechaVisitaParsed);

                                    idVisita = (int)await cmd.ExecuteScalarAsync();
                                }

                                // 🔹 Obtener datos para email
                                string clienteNom = "", clienteDir = "", clienteCoord = "", clienteMail = "";
                                string tecnicoNom = "", tecnicoMail = "";

                                // Cliente
                                using (var cmd = new SqlCommand(@"
                                    SELECT nombre, direccion, coordenadas, correo
                                    FROM TBL_CLIENTES WHERE id_cliente=@id", cn))
                                {
                                    cmd.Parameters.AddWithValue("@id", dto.id_cliente);
                                    using var rd = await cmd.ExecuteReaderAsync();
                                    if (await rd.ReadAsync())
                                    {
                                        clienteNom = rd.GetString(0);
                                        clienteDir = rd.IsDBNull(1) ? "" : rd.GetString(1);
                                        clienteCoord = rd.IsDBNull(2) ? "" : rd.GetString(2);
                                        clienteMail = rd.IsDBNull(3) ? "" : rd.GetString(3);
                                    }
                                }

                                // Técnico
                                using (var cmd = new SqlCommand(@"
                                    SELECT IU.nombre, IU.correo
                                    FROM TBL_INFO_USUARIO IU
                                    INNER JOIN TBL_USUARIO U ON U.id_usuario = IU.id_usuario
                                    WHERE U.id_usuario=@id", cn))
                                {
                                    cmd.Parameters.AddWithValue("@id", dto.id_tecnico);
                                    using var rd = await cmd.ExecuteReaderAsync();
                                    if (await rd.ReadAsync())
                                    {
                                        tecnicoNom = rd.GetString(0);
                                        tecnicoMail = rd.IsDBNull(1) ? "" : rd.GetString(1);
                                    }
                                }

                                // 🔹 Enviar email en segundo plano
                                _ = Task.Run(() =>
                                {
                                    try
                                    {
                                        var emailService = context.RequestServices.GetService<SkynetApiAuth.Services.EmailService>();
                                        emailService?.SendVisitaAsignadaEmails(
                                            clienteMail,
                                            tecnicoMail,
                                            clienteNom,
                                            clienteDir,
                                            clienteCoord,
                                            tecnicoNom,
                                            dto.fecha_visita
                                        );

                                        Console.WriteLine($"📨 Email de visita #{idVisita} enviado. IP: {clientIp}");
                                    }
                                    catch (Exception ex)
                                    {
                                        Console.WriteLine($"❌ Error al enviar email visita #{idVisita}: {ex.Message}. IP: {clientIp}");
                                    }
                                });

                                return Results.Ok(new
                                {
                                    message = "✅ Visita creada correctamente",
                                    id_visita = idVisita,
                                    cliente = clienteNom,
                                    tecnico = tecnicoNom,
                                    fecha_visita = fechaVisitaParsed.ToString("yyyy-MM-dd")
                                });
                            }
                            catch (SqlException ex)
                            {
                                return Results.Problem($"❌ Error SQL al crear la visita:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                            }
                            catch (Exception ex)
                            {
                                return Results.Problem($"❌ Error inesperado:\n{ex.Message}\n\n🌐 IP: {clientIp}");
                            }
                        });


                        app.MapPut("/api/visitas/{id:int}", async (int id, VisitaUpdateDto dto) =>
                        {
                            var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

                            if (dto == null)
                                return Results.BadRequest(new { message = "Datos inválidos" });

                            // Validación mínima
                            if (dto.id_cliente <= 0 || dto.id_supervisor <= 0 || dto.id_tecnico <= 0)
                                return Results.BadRequest(new { message = "Cliente, Supervisor y Técnico son obligatorios" });

                            if (!DateTime.TryParse(dto.fecha_visita, out var fechaVisitaParsed))
                                return Results.BadRequest(new { message = "El campo fecha_visita no es válido. Formato esperado: yyyy-MM-dd" });

                            using var cn = new SqlConnection(connectionString);
                            await cn.OpenAsync();

                            using var tx = cn.BeginTransaction();

                            try
                            {
                                int oldTec = 0;
                                using (var cmd = new SqlCommand("SELECT id_tecnico FROM TBL_VISITA WHERE id_visita=@id", cn, tx))
                                {
                                    cmd.Parameters.AddWithValue("@id", id);
                                    var obj = await cmd.ExecuteScalarAsync();
                                    if (obj == null)
                                        return Results.NotFound(new { message = "Visita no encontrada" });

                                    oldTec = Convert.ToInt32(obj);
                                }

                                // Update
                                var qUp = @"
                                    UPDATE TBL_VISITA
                                    SET id_cliente=@c, id_supervisor=@s, id_tecnico=@t, fecha_visita=@f, coordenadas_planificadas=@coord
                                    WHERE id_visita=@id";

                                using (var cmd = new SqlCommand(qUp, cn, tx))
                                {
                                    cmd.Parameters.AddWithValue("@c", dto.id_cliente);
                                    cmd.Parameters.AddWithValue("@s", dto.id_supervisor);
                                    cmd.Parameters.AddWithValue("@t", dto.id_tecnico);
                                    cmd.Parameters.AddWithValue("@f", fechaVisitaParsed);
                                    cmd.Parameters.AddWithValue("@coord", (object?)dto.coordenadas_planificadas ?? DBNull.Value);
                                    cmd.Parameters.AddWithValue("@id", id);
                                    await cmd.ExecuteNonQueryAsync();
                                }

                                tx.Commit();

                                // Si cambió técnico → enviar correo (NO MODIFICADO, QUEDA IGUAL)
                                if (dto.id_tecnico != oldTec)
                                {
                                    string clienteNom = "", clienteDir = "", clienteCoord = "";
                                    string tecnicoNom = "", tecnicoUser = "", tecnicoMail = "";

                                    // Cliente
                                    using (var cmd = new SqlCommand(@"
                                        SELECT nombre, direccion, coordenadas
                                        FROM TBL_CLIENTES WHERE id_cliente=@c", cn))
                                    {
                                        cmd.Parameters.AddWithValue("@c", dto.id_cliente);
                                        using var rd = await cmd.ExecuteReaderAsync();
                                        if (await rd.ReadAsync())
                                        {
                                            clienteNom = rd.GetString(0);
                                            clienteDir = rd.IsDBNull(1) ? "" : rd.GetString(1);
                                            clienteCoord = rd.IsDBNull(2) ? "" : rd.GetString(2);
                                        }
                                    }

                                    // Técnico nuevo
                                    using (var cmd = new SqlCommand(@"
                                        SELECT IU.nombre, U.usuario, IU.correo
                                        FROM TBL_INFO_USUARIO IU
                                        INNER JOIN TBL_USUARIO U ON U.id_usuario = IU.id_usuario
                                        WHERE U.id_usuario=@t", cn))
                                    {
                                        cmd.Parameters.AddWithValue("@t", dto.id_tecnico);
                                        using var rd = await cmd.ExecuteReaderAsync();
                                        if (await rd.ReadAsync())
                                        {
                                            tecnicoNom = rd.GetString(0);
                                            tecnicoUser = rd.GetString(1);
                                            tecnicoMail = rd.IsDBNull(2) ? "" : rd.GetString(2);
                                        }
                                    }

                                    // ✅ BLOQUE DE EMAIL — SIN MODIFICAR
                                    await EmailService.SendAvisoTecnicoReasignado(cn, new EmailVisitaData
                                    {
                                        IdVisita = id,
                                        ClienteNombre = clienteNom,
                                        ClienteDireccion = clienteDir,
                                        ClienteCoordenadas = clienteCoord,
                                        TecnicoNombre = tecnicoNom,
                                        TecnicoUsuario = tecnicoUser,
                                        TecnicoEmail = tecnicoMail,
                                        FechaVisita = fechaVisitaParsed,
                                        CoordenadasPlan = dto.coordenadas_planificadas
                                    });
                                }

                                return Results.Ok(new { message = "Visita actualizada correctamente" });
                            }
                            catch (SqlException ex)
                            {
                                tx.Rollback();
                                return Results.Problem($"❌ Error SQL al actualizar la visita:\n{ex.Message}");
                            }
                            catch (Exception ex)
                            {
                                tx.Rollback();
                                return Results.Problem($"❌ Error inesperado:\n{ex.Message}");
                            }
                        });








                app.MapGet("/api/usuarios/{id:int}/asignaciones", async (int id) =>
                {
                    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

                    using var cn = new SqlConnection(connectionString);
                    await cn.OpenAsync();

                    try
                    {
                        // 1️⃣ Validar existencia del usuario y obtener rol
                        string? rol = null;
                        using (var cmd = new SqlCommand(@"
                            SELECT R.descripcion
                            FROM TBL_USUARIO U
                            INNER JOIN TBL_ROL R ON R.id_rol = U.id_rol
                            WHERE U.id_usuario = @id", cn))
                        {
                            cmd.Parameters.AddWithValue("@id", id);
                            rol = (string?)await cmd.ExecuteScalarAsync();
                        }

                        if (rol == null)
                            return Results.NotFound(new { message = "Usuario no encontrado" });

                        rol = rol.ToUpper();

                        // 2️⃣ Si es SUPERVISOR → obtener técnicos asignados
                        if (rol == "SUPERVISOR")
                        {
                            var tecnicos = new List<int>();

                            using var cmd = new SqlCommand(@"
                                SELECT id_tecnico
                                FROM TBL_SUPERVISOR_TECNICO
                                WHERE id_supervisor=@id
                                ORDER BY id_tecnico", cn);

                            cmd.Parameters.AddWithValue("@id", id);

                            using var rd = await cmd.ExecuteReaderAsync();
                            while (await rd.ReadAsync())
                                tecnicos.Add(rd.GetInt32(0));

                            return Results.Ok(new
                            {
                                tipo = "SUPERVISOR",
                                supervisor_asignado = (int?)null,
                                tecnicos_asignados = tecnicos,
                                total_tecnicos = tecnicos.Count
                            });
                        }

                        // 3️⃣ Si es TECNICO → obtener su supervisor
                        if (rol == "TECNICO")
                        {
                            int? supervisor = null;

                            using var cmd = new SqlCommand(@"
                                SELECT TOP 1 id_supervisor
                                FROM TBL_SUPERVISOR_TECNICO
                                WHERE id_tecnico=@id", cn);

                            cmd.Parameters.AddWithValue("@id", id);

                            var result = await cmd.ExecuteScalarAsync();
                            if (result != null && result != DBNull.Value)
                                supervisor = Convert.ToInt32(result);

                            return Results.Ok(new
                            {
                                tipo = "TECNICO",
                                supervisor_asignado = supervisor,
                                tecnicos_asignados = Array.Empty<int>(),
                                total_tecnicos = 0
                            });
                        }

                        // 4️⃣ Si es ADMIN o cualquier otro
                        return Results.Ok(new
                        {
                            tipo = rol, // mostrará ADMINISTRADOR / CLIENTE / ETC
                            supervisor_asignado = (int?)null,
                            tecnicos_asignados = Array.Empty<int>(),
                            total_tecnicos = 0
                        });
                    }
                    catch (SqlException ex)
                    {
                        return Results.Problem($"❌ Error SQL al consultar asignaciones:\n{ex.Message}");
                    }
                    catch (Exception ex)
                    {
                        return Results.Problem($"❌ Error inesperado:\n{ex.Message}");
                    }
                });


        // PUT /api/usuarios/{id}/asignaciones
        // Solo ADMIN puede modificar.
        // Payload según tipo:
        //  - SUPERVISOR: { "tecnicos": [1,2,3] }
        //  - TECNICO:    { "id_supervisor": 10 }
app.MapPut("/api/usuarios/{id:int}/asignaciones", async (int id, HttpRequest req) =>
{
    var cs = builder.Configuration.GetConnectionString("DefaultConnection");

    // Obtiene rol desde headers (código o descripción)
    var rolHdr = (req.Headers["rol"].ToString() ?? "").ToUpper();
    var rolNombreHdr = (req.Headers["rol_nombre"].ToString() ?? "").ToUpper();

    bool isAdmin =
        rolHdr == "ADMIN" ||
        rolNombreHdr == "ADMINISTRADOR";

    if (!isAdmin)
        return Results.Json(new { message = "No autorizado" }, statusCode: 401);

    using var cn = new SqlConnection(cs);
    await cn.OpenAsync();

    // Obtener tipo de usuario objetivo (SUPERVISOR / TECNICO / OTRO)
    string tipo = "OTRO";
    using (var cmd = new SqlCommand(@"
        SELECT R.descripcion
        FROM TBL_USUARIO U
        INNER JOIN TBL_ROL R ON R.id_rol = U.id_rol
        WHERE U.id_usuario = @id", cn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        var rolDb = (string?)await cmd.ExecuteScalarAsync();
        if (!string.IsNullOrWhiteSpace(rolDb))
            tipo = rolDb.ToUpper();
    }

    // Leer body
    string body = await new StreamReader(req.Body).ReadToEndAsync();
    using var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(body) ? "{}" : body);
    var root = doc.RootElement;

    // 🧩 SUPERVISOR — Reemplaza todos los técnicos asignados
    if (tipo == "SUPERVISOR")
    {
        var tecnicos = new List<int>();

        if (root.TryGetProperty("tecnicos", out var arr) && arr.ValueKind == JsonValueKind.Array)
        {
            foreach (var x in arr.EnumerateArray())
                if (x.ValueKind == JsonValueKind.Number)
                    tecnicos.Add(x.GetInt32());
        }

        using var tx = cn.BeginTransaction();

        // Borrar asignaciones previas
        using (var del = new SqlCommand(
            "DELETE FROM TBL_SUPERVISOR_TECNICO WHERE id_supervisor=@sup", cn, tx))
        {
            del.Parameters.AddWithValue("@sup", id);
            await del.ExecuteNonQueryAsync();
        }

        // Insertar nuevas asignaciones
        foreach (var t in tecnicos.Distinct())
        {
            using var ins = new SqlCommand(@"
                INSERT INTO TBL_SUPERVISOR_TECNICO (id_supervisor, id_tecnico)
                VALUES (@sup, @tec)", cn, tx);

            ins.Parameters.AddWithValue("@sup", id);
            ins.Parameters.AddWithValue("@tec", t);
            await ins.ExecuteNonQueryAsync();
        }

        await tx.CommitAsync();

        return Results.Ok(new
        {
            message = "Asignaciones actualizadas (supervisor → técnicos)",
            total_asignados = tecnicos.Distinct().Count()
        });
    }

    // 🔧 TECNICO — Asignar o remover supervisor
    if (tipo == "TECNICO")
    {
        int? idSup = null;
        if (root.TryGetProperty("id_supervisor", out var supEl) && supEl.ValueKind == JsonValueKind.Number)
            idSup = supEl.GetInt32();

        using var tx = cn.BeginTransaction();

        if (idSup is null)
        {
            // Quitar supervisor
            using var del = new SqlCommand(
                "DELETE FROM TBL_SUPERVISOR_TECNICO WHERE id_tecnico=@tec", cn, tx);

            del.Parameters.AddWithValue("@tec", id);
            await del.ExecuteNonQueryAsync();

            await tx.CommitAsync();
            return Results.Ok(new { message = "Supervisor desasignado del técnico" });
        }

        // Verificar si ya tiene supervisor
        int existe;
        using (var chk = new SqlCommand(
            "SELECT COUNT(*) FROM TBL_SUPERVISOR_TECNICO WHERE id_tecnico=@tec", cn, tx))
        {
            chk.Parameters.AddWithValue("@tec", id);
            existe = Convert.ToInt32(await chk.ExecuteScalarAsync());
        }

        if (existe > 0)
        {
            using var up = new SqlCommand(@"
                UPDATE TBL_SUPERVISOR_TECNICO 
                SET id_supervisor=@sup 
                WHERE id_tecnico=@tec", cn, tx);

            up.Parameters.AddWithValue("@sup", idSup);
            up.Parameters.AddWithValue("@tec", id);
            await up.ExecuteNonQueryAsync();
        }
        else
        {
            using var ins = new SqlCommand(@"
                INSERT INTO TBL_SUPERVISOR_TECNICO (id_supervisor, id_tecnico)
                VALUES (@sup, @tec)", cn, tx);

            ins.Parameters.AddWithValue("@sup", idSup);
            ins.Parameters.AddWithValue("@tec", id);
            await ins.ExecuteNonQueryAsync();
        }

        await tx.CommitAsync();
        return Results.Ok(new { message = "Supervisor asignado al técnico" });
    }

    return Results.BadRequest(new { message = "El usuario indicado no es SUPERVISOR ni TECNICO" });
});



            app.MapPut("/api/supervisores/{id:int}/tecnicos", async (int id, HttpRequest request) =>
            {
                // Validación de rol por header
                var rolHeader = (request.Headers["rol"].ToString() ?? "").ToUpper();
                if (rolHeader != "ADMIN" && rolHeader != "ADMINISTRADOR")
                    return Results.Json(new { message = "No autorizado" }, statusCode: 401);

                // Leer body
                var dto = await request.ReadFromJsonAsync<AsignarTecnicosDto>();
                if (dto is null)
                    return Results.BadRequest(new { message = "Datos inválidos" });

                var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

                using var con = new SqlConnection(connectionString);
                await con.OpenAsync();

                using var tx = con.BeginTransaction();

                try
                {
                    // 1️⃣ Eliminar asignaciones anteriores del supervisor
                    using (var del = new SqlCommand(
                        "DELETE FROM TBL_SUPERVISOR_TECNICO WHERE id_supervisor = @sup", con, tx))
                    {
                        del.Parameters.AddWithValue("@sup", id);
                        await del.ExecuteNonQueryAsync();
                    }

                    // 2️⃣ Insertar nuevas asignaciones
                    int totalAsignados = 0;

                    if (dto.tecnicos is not null && dto.tecnicos.Count > 0)
                    {
                        foreach (var tecId in dto.tecnicos.Distinct())
                        {
                            using var ins = new SqlCommand(@"
                                INSERT INTO TBL_SUPERVISOR_TECNICO (id_supervisor, id_tecnico)
                                VALUES (@sup, @tec)", con, tx);

                            ins.Parameters.AddWithValue("@sup", id);
                            ins.Parameters.AddWithValue("@tec", tecId);

                            await ins.ExecuteNonQueryAsync();
                            totalAsignados++;
                        }
                    }

                    await tx.CommitAsync();

                    return Results.Ok(new
                    {
                        message = "Asignaciones actualizadas correctamente",
                        total = totalAsignados
                    });
                }
                catch (Exception ex)
                {
                    tx.Rollback();
                    return Results.Problem($"❌ Error al actualizar asignaciones:\n{ex.Message}");
                }
            });



                app.MapPost("/api/visitas/{id:int}/procesar", async (int id, ProcesarVisitaDto dto) =>
                {
                    var connectionString =
                        Environment.GetEnvironmentVariable("DefaultConnection") // Render / Producción
                        ?? builder.Configuration.GetConnectionString("DefaultConnection"); // Local

                    // Validaciones básicas
                    var estadosPermitidos = new[] { "EN_PROGRESO", "COMPLETADA", "CANCELADA" };
                    var nuevoEstado = (dto.nuevo_estado ?? "").ToUpper();
                    if (!estadosPermitidos.Contains(nuevoEstado))
                        return Results.BadRequest(new { message = "Estado inválido" });

                    if (string.IsNullOrWhiteSpace(dto.observaciones))
                        return Results.BadRequest(new { message = "Las observaciones son obligatorias" });

                    using var cn = new SqlConnection(connectionString);
                    await cn.OpenAsync();

                    using var tx = cn.BeginTransaction();

                    // Traer visita para obtener coordenadas planificadas y validar existencia
                    string? coordPlanificadas = null;
                    using (var cmd = new SqlCommand("SELECT coordenadas_planificadas FROM TBL_VISITA WHERE id_visita=@id", cn, tx))
                    {
                        cmd.Parameters.AddWithValue("@id", id);
                        var obj = await cmd.ExecuteScalarAsync();
                        if (obj == null)
                        {
                            tx.Rollback();
                            return Results.NotFound(new { message = "Visita no encontrada" });
                        }
                        coordPlanificadas = obj == DBNull.Value ? null : Convert.ToString(obj);
                    }

                    // Resolver coordenadas a guardar en detalle
                    string? coordFinal = dto.usar_planificadas
                        ? (coordPlanificadas ?? "")
                        : (dto.coordenadas_nuevas ?? "");

                    // UPDATE estado en encabezado
                    using (var cmd = new SqlCommand("UPDATE TBL_VISITA SET estado=@e WHERE id_visita=@id", cn, tx))
                    {
                        cmd.Parameters.AddWithValue("@e", nuevoEstado);
                        cmd.Parameters.AddWithValue("@id", id);
                        await cmd.ExecuteNonQueryAsync();
                    }

                    // INSERT detalle (fecha_atencion = GETDATE())
                    using (var cmd = new SqlCommand(@"
                        INSERT INTO TBL_DETALLE_VISITA (id_visita, fecha_atencion, observaciones, coordenadas_visita)
                        VALUES (@v, GETDATE(), @obs, @coords)", cn, tx))
                    {
                        cmd.Parameters.AddWithValue("@v", id);
                        cmd.Parameters.AddWithValue("@obs", dto.observaciones);
                        cmd.Parameters.AddWithValue("@coords", (object?)coordFinal ?? DBNull.Value);
                        await cmd.ExecuteNonQueryAsync();
                    }

                    tx.Commit();

                    string correoCliente = "";
                    string correoSupervisor = "";
                    string tecnicoNom = "";
                    string fechaAtencion = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                    string coordenadasFinales = coordFinal ?? "";

                    // Obtener correo del cliente
                    using (var cmd = new SqlCommand(@"
                    SELECT correo FROM TBL_CLIENTES
                    WHERE id_cliente = (SELECT id_cliente FROM TBL_VISITA WHERE id_visita = @id)", cn))
                    {
                        cmd.Parameters.AddWithValue("@id", id);
                        var cli = await cmd.ExecuteScalarAsync();
                        correoCliente = cli == null ? "" : cli.ToString()!;
                    }

                    // Obtener correo del Supervisor
                    using (var cmd = new SqlCommand(@"
                    SELECT IU.correo
                    FROM TBL_INFO_USUARIO IU
                    WHERE IU.id_usuario = (SELECT id_supervisor FROM TBL_VISITA WHERE id_visita = @id)", cn))
                    {
                        cmd.Parameters.AddWithValue("@id", id);
                        var sup = await cmd.ExecuteScalarAsync();
                        correoSupervisor = sup == null ? "" : sup.ToString()!;
                    }

                    // Obtener nombre del Técnico que atendió
                    using (var cmd = new SqlCommand(@"
                    SELECT IU.nombre
                    FROM TBL_INFO_USUARIO IU
                    WHERE IU.id_usuario = (SELECT id_tecnico FROM TBL_VISITA WHERE id_visita = @id)", cn))
                    {
                        cmd.Parameters.AddWithValue("@id", id);
                        var tec = await cmd.ExecuteScalarAsync();
                        tecnicoNom = tec == null ? "Técnico" : tec.ToString()!;
                    }

                    // PRINT EN CONSOLA
                    Console.WriteLine($@"
                ---- Enviando correo de VISITA PROCESADA ----
                Cliente: {correoCliente}
                Supervisor: {correoSupervisor}
                Técnico: {tecnicoNom}
                Fecha Atención: {fechaAtencion}
                Coordenadas Finales: {coordenadasFinales}
                --------------------------------------------------
                ");

                    try
                    {
                        var emailService = app.Services.GetService<SkynetApiAuth.Services.EmailService>();
                        emailService?.SendVisitaProcesadaEmail(
                            correoCliente,
                            correoSupervisor,
                            tecnicoNom,
                            fechaAtencion,
                            coordenadasFinales
                        );

                        Console.WriteLine("✅ Correo enviado correctamente.");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("❌ Error al enviar correo: " + ex.Message);
                    }

                    return Results.Ok(new { message = "Visita procesada" });
                });



        app.MapGet("/", () => Results.Ok("✅ API Skynet Auth corriendo en Render"));
        app.MapGet("/ping", () => Results.Ok("pong ✅"));

        // ================== RUN ==================
        app.Run();
    }


    public record ClienteDto(
                string nombre,
                string? nit,
                string? direccion,
                string? coordenadas,
                string? correo
            );

    public record ClienteUpdateDto(
        string nombre,
        string? nit,
        string? direccion,
        string? coordenadas,
        string? correo,
        bool activo
    );

    // ================== RECORDS & HELPERS ==================
    public record LoginRequest(string usuario, string clave);

    public record UserCreateDto(
        string nombre,
        string correo,
        string usuario,
        string clave,
        int id_rol,
        string rol,
        int? id_supervisor
    );

    public record UserUpdateDto(
        string nombre,
        string correo,
        string usuario,
        int id_rol,
        bool activo,
        string? clave,
        string rol,
        int? id_supervisor
    );



    public static string HashSHA256(string input)
    {
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(input);
        var hashBytes = sha256.ComputeHash(bytes);
        return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
    }
}



public class EmailVisitaData{
    public int IdVisita { get; set; }
    public string ClienteNombre { get; set; } = "";
    public string ClienteDireccion { get; set; } = "";
    public string ClienteCoordenadas { get; set; } = "";
    public string ClienteEmail { get; set; } = "";
    public string TecnicoNombre { get; set; } = "";
    public string TecnicoUsuario { get; set; } = "";
    public string TecnicoEmail { get; set; } = "";
    public DateTime FechaVisita { get; set; }
    public string CoordenadasPlan { get; set; } = "";
}

public static class EmailService
{
    private static async Task<(SmtpClient smtp, string from, string fromName)> BuildSmtpAsync(SqlConnection cn)
    {
        string host="", user="", pass="", from="", fromName="SkyNet";
        int port=587; bool ssl=true;

        using var cmd = new SqlCommand(@"
            SELECT TOP 1 servidor_smtp, puerto, usa_ssl, usuario_correo, clave_correo, correo_emisor, remitente_nombre
            FROM TBL_CONFIG_CORREO
            WHERE activo=1
            ORDER BY fecha_configuracion DESC", cn);
        using var rd = await cmd.ExecuteReaderAsync();
        if (await rd.ReadAsync())
        {
            host = rd.GetString(0);
            port = rd.GetInt32(1);
            ssl = rd.GetBoolean(2);
            user = rd.IsDBNull(3) ? "" : rd.GetString(3);
            pass = rd.IsDBNull(4) ? "" : rd.GetString(4);
            from = rd.IsDBNull(5) ? "" : rd.GetString(5);
            fromName = rd.IsDBNull(6) ? fromName : rd.GetString(6);
        }

        var smtp = new SmtpClient(host, port){
            EnableSsl = ssl,
            DeliveryMethod = SmtpDeliveryMethod.Network,
            Credentials = string.IsNullOrWhiteSpace(user) ? CredentialCache.DefaultNetworkCredentials
                      : new NetworkCredential(user, pass)
        };
        return (smtp, from, fromName);
    }

    private static string MapLink(string coords) =>
        string.IsNullOrWhiteSpace(coords) ? "#" : $"https://www.google.com/maps?q={coords}";

    public static async Task SendVisitaAsignadaEmail(SqlConnection cn, EmailVisitaData data)
    {
        var (smtp, from, fromName) = await BuildSmtpAsync(cn);
        var subject = $"[SkyNet] Nueva visita #{data.IdVisita} — {data.ClienteNombre}";
        var html = $@"
            <h3>Visita programada</h3>
            <p><b>Cliente:</b> {data.ClienteNombre}</p>
            <p><b>Dirección:</b> {data.ClienteDireccion}</p>
            <p><b>Fecha visita:</b> {data.FechaVisita:yyyy-MM-dd}</p>
            <p><b>Técnico asignado:</b> {data.TecnicoNombre} ({data.TecnicoUsuario})</p>
            <p><a href=""{MapLink(data.CoordenadasPlan)}"">Ver ubicación planificada</a></p>
            {(string.IsNullOrWhiteSpace(data.ClienteCoordenadas) ? "" : $"<p><a href=\"{MapLink(data.ClienteCoordenadas)}\">Ver ubicación de cliente</a></p>")}
        ";

        // Email a técnico
        if (!string.IsNullOrWhiteSpace(data.TecnicoEmail))
        {
            var m = new MailMessage(){ From = new MailAddress(from, fromName), Subject = subject, Body = html, IsBodyHtml = true };
            m.To.Add(data.TecnicoEmail);
            await smtp.SendMailAsync(m);
        }

        // Email a cliente
        if (!string.IsNullOrWhiteSpace(data.ClienteEmail))
        {
            var m = new MailMessage(){ From = new MailAddress(from, fromName), Subject = subject, Body = html, IsBodyHtml = true };
            m.To.Add(data.ClienteEmail);
            await smtp.SendMailAsync(m);
        }
    }

    public static async Task SendAvisoTecnicoReasignado(SqlConnection cn, EmailVisitaData data)
    {
        var (smtp, from, fromName) = await BuildSmtpAsync(cn);
        var subject = $"[SkyNet] Visita #{data.IdVisita} — Técnico reasignado";
        var html = $@"
            <h3>Reasignación de técnico</h3>
            <p><b>Cliente:</b> {data.ClienteNombre}</p>
            <p><b>Fecha visita:</b> {data.FechaVisita:yyyy-MM-dd}</p>
            <p><b>Nuevo técnico:</b> {data.TecnicoNombre} ({data.TecnicoUsuario})</p>
            <p><a href=""{MapLink(data.CoordenadasPlan)}"">Ver ubicación planificada</a></p>
        ";

        if (!string.IsNullOrWhiteSpace(data.TecnicoEmail))
        {
            var m = new MailMessage(){ From = new MailAddress(from, fromName), Subject = subject, Body = html, IsBodyHtml = true };
            m.To.Add(data.TecnicoEmail);
            await smtp.SendMailAsync(m);
        }
    }
}

public record AsignarTecnicosDto(List<int> tecnicos);
public record VisitaCreateDto(
    int id_cliente,
    int id_supervisor,
    int id_tecnico,
    string coordenadas_planificadas,
    string fecha_visita
);

public record VisitaUpdateDto(
    int id_cliente,
    int id_supervisor,
    int id_tecnico,
    string coordenadas_planificadas,
    string fecha_visita
);

public record ProcesarVisitaDto(
    string nuevo_estado,           // "EN_PROGRESO" | "COMPLETADA" | "CANCELADA"
    string observaciones,          // obligatorio
    bool usar_planificadas,        // true = usar V.coordenadas_planificadas
    string? coordenadas_nuevas     // si usar_planificadas = false, debe venir aquí "lat,lng"
);
