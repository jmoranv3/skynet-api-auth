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


        // JSON case sensitivity: enforce exact property names (no case-insensitive binding)
        builder.Services.ConfigureHttpJsonOptions(options =>
        {
            options.SerializerOptions.PropertyNameCaseInsensitive = false;
        });

        builder.Services.AddCors(options =>
        {
            options.AddPolicy("AllowReactApp",
                policy => policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
        });

        builder.Configuration
    .SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
    .AddEnvironmentVariables();


        var app = builder.Build();

        app.UseCors("AllowReactApp");

        // ================== AUTH ==================
        app.MapPost("/auth/login", async (LoginRequest login) =>
        {

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
    catch (Exception ex)
    {
        return Results.Problem($"❌ Error al conectar a SQL Server:\n{ex.Message}");
    }
        });

        app.MapPost("/auth/hash", async (HttpRequest request) =>
        {
            using var reader = new StreamReader(request.Body);
            var texto = await reader.ReadToEndAsync();
            return HashSHA256(texto.Replace("\"", ""));
        });

        // ================== CLIENTES ==================
        app.MapGet("/api/clientes", async (HttpRequest request) =>
        {
            var rol = request.Headers["rol"].ToString().ToUpper();

            var rolesPermitidos = new[] { "ADMINISTRADOR", "SUPERVISOR", "TECNICO" };

            if (!rolesPermitidos.Contains(rol))
                return Results.Unauthorized();

            var clientes = new List<object>();
            var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

            using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync();

            var query = @"SELECT id_cliente, nombre, nit, direccion, coordenadas, correo, activo, fecha_creacion 
                          FROM TBL_CLIENTES";

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

            return Results.Ok(clientes);
        });

        // ================== DASHBOARD ==================
app.MapGet("/api/dashboard/visitas/programadas", async (HttpRequest request) =>
{
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

    string rol = request.Headers["rol"].ToString().ToUpper();
    int idUsuario = int.Parse(request.Headers["id_usuario"]);


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
       ;
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
});

app.MapGet("/api/dashboard/visitas/completadas", async (HttpRequest request) =>
{
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

    string rol = request.Headers["rol"].ToString().ToUpper();
    int idUsuario = int.Parse(request.Headers["id_usuario"]);

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
        INNER JOIN  TBL_USUARIO U ON V.id_tecnico = U.id_usuario
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
});


app.MapGet("/api/dashboard/visitas/pendientes", async (HttpRequest request) =>
{
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

    string rol = request.Headers["rol"].ToString().ToUpper();
    int idUsuario = int.Parse(request.Headers["id_usuario"]);

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

    string whereClause = "WHERE V.estado in ('PENDIENTE','EN_PROGRESO')";

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
});


        // ============================= CRUD USUARIOS - SKYNET =============================
        // BASE URL: /api/usuarios
        // ================================================================================

        // Listar usuarios
        app.MapGet("/api/usuarios", async () =>
        {
            var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
            var usuarios = new List<object>();

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

            return Results.Ok(usuarios);
        });

        // Listar supervisores
        app.MapGet("/api/usuarios/supervisores", async () =>
        {
            var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
            var supervisores = new List<object>();

            using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync();

            var query = @"
                SELECT IU.id_usuario, IU.nombre, IU.correo, U.usuario, U.activo
                FROM TBL_INFO_USUARIO IU
                INNER JOIN TBL_USUARIO U ON U.id_usuario = IU.id_usuario
                INNER JOIN TBL_ROL R ON R.id_rol = U.id_rol
                WHERE R.descripcion = 'SUPERVISOR'
                ORDER BY IU.nombre";

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

            return Results.Ok(supervisores);
        });

        // Listar técnicos
        app.MapGet("/api/usuarios/tecnicos", async () =>
        {
            var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
            var tecnicos = new List<object>();

            using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync();

            var query = @"
                SELECT IU.id_usuario, IU.nombre, IU.correo, U.usuario, U.activo
                FROM TBL_INFO_USUARIO IU
                INNER JOIN TBL_USUARIO U ON U.id_usuario = IU.id_usuario
                INNER JOIN TBL_ROL R ON R.id_rol = U.id_rol
                WHERE R.descripcion = 'TECNICO'
                ORDER BY IU.nombre";

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

            return Results.Ok(tecnicos);
        });

        // Crear usuario
        app.MapPost("/api/usuarios", async (UserCreateDto dto) =>
        {
            var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

            if (dto is null)
                return Results.BadRequest(new { message = "Datos inválidos" });

            // Validación: Si rol es TECNICO, supervisor es obligatorio
            if (dto.rol.ToUpper() == "TECNICO" && dto.id_supervisor is null)
                return Results.BadRequest(new { message = "Debe seleccionar un supervisor para el técnico." });

            using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync();

            // Validar usuario duplicado
            var checkUserQuery = "SELECT COUNT(*) FROM TBL_USUARIO WHERE usuario = @usuario";
            using (var checkCmd = new SqlCommand(checkUserQuery, connection))
            {
                checkCmd.Parameters.AddWithValue("@usuario", dto.usuario);
                int exists = (int)await checkCmd.ExecuteScalarAsync();
                if (exists > 0)
                    return Results.BadRequest(new { message = "El usuario ya existe, elija otro." });
            }

            var hashedPassword = HashSHA256(dto.clave);

            // 1) Insertar TBL_INFO_USUARIO
            var cmdInfo = new SqlCommand(
                "INSERT INTO TBL_INFO_USUARIO (nombre, correo) OUTPUT INSERTED.id_usuario VALUES (@nombre, @correo)", connection);
            cmdInfo.Parameters.AddWithValue("@nombre", dto.nombre);
            cmdInfo.Parameters.AddWithValue("@correo", dto.correo);

            int newId = (int)await cmdInfo.ExecuteScalarAsync();

            // 2) Insertar TBL_USUARIO
            var cmdUser = new SqlCommand(
                "INSERT INTO TBL_USUARIO (id_usuario, usuario, clave, id_rol) VALUES (@id_usuario, @usuario, @clave, @id_rol)", connection);
            cmdUser.Parameters.AddWithValue("@id_usuario", newId);
            cmdUser.Parameters.AddWithValue("@usuario", dto.usuario);
            cmdUser.Parameters.AddWithValue("@clave", hashedPassword);
            cmdUser.Parameters.AddWithValue("@id_rol", dto.id_rol);
            await cmdUser.ExecuteNonQueryAsync();

            // 3) Si es técnico, asignar supervisor
            if (dto.rol.ToUpper() == "TECNICO")
            {
                var cmdSup = new SqlCommand(
                    "INSERT INTO TBL_SUPERVISOR_TECNICO (id_supervisor, id_tecnico) VALUES (@id_sup, @id_tec)", connection);
                cmdSup.Parameters.AddWithValue("@id_sup", dto.id_supervisor);
                cmdSup.Parameters.AddWithValue("@id_tec", newId);
                await cmdSup.ExecuteNonQueryAsync();
            }

            try
                {
                    var emailService = app.Services.GetService<SkynetApiAuth.Services.EmailService>();
                    emailService?.SendUserCredentials(dto.correo, dto.usuario, dto.clave, dto.rol, dto.nombre);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error al enviar correo: " + ex.Message);
                }


            return Results.Ok(new { message = "Usuario creado exitosamente", id_usuario = newId });
        });

        // Actualizar usuario
        app.MapPut("/api/usuarios/{id:int}", async (int id, UserUpdateDto dto) =>
        {
            var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

            if (dto is null)
                return Results.BadRequest(new { message = "Datos inválidos" });

            using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync();

            // Validar existencia del usuario
            var existsCmd = new SqlCommand("SELECT COUNT(*) FROM TBL_USUARIO WHERE id_usuario = @id", connection);
            existsCmd.Parameters.AddWithValue("@id", id);
            if ((int)await existsCmd.ExecuteScalarAsync() == 0)
                return Results.NotFound(new { message = "Usuario no encontrado" });

            // Validación: Si rol es TECNICO, supervisor es obligatorio
            if (dto.rol.ToUpper() == "TECNICO" && dto.id_supervisor is null)
                return Results.BadRequest(new { message = "Debe seleccionar un supervisor para el técnico." });

            // Validación: Usuario duplicado (excepto él mismo)
            var checkUserQuery = "SELECT COUNT(*) FROM TBL_USUARIO WHERE usuario = @usuario AND id_usuario <> @id";
            using (var checkCmd = new SqlCommand(checkUserQuery, connection))
            {
                checkCmd.Parameters.AddWithValue("@usuario", dto.usuario);
                checkCmd.Parameters.AddWithValue("@id", id);
                int exists = (int)await checkCmd.ExecuteScalarAsync();
                if (exists > 0)
                    return Results.BadRequest(new { message = "El usuario ya está en uso, elija otro." });
            }

            // Actualizar TBL_INFO_USUARIO
            var cmdInfo = new SqlCommand(
                "UPDATE TBL_INFO_USUARIO SET nombre=@nombre, correo=@correo WHERE id_usuario=@id", connection);
            cmdInfo.Parameters.AddWithValue("@nombre", dto.nombre);
            cmdInfo.Parameters.AddWithValue("@correo", dto.correo);
            cmdInfo.Parameters.AddWithValue("@id", id);
            await cmdInfo.ExecuteNonQueryAsync();

            // Actualizar TBL_USUARIO (sin clave aún)
            var cmdUser = new SqlCommand(
                "UPDATE TBL_USUARIO SET usuario=@usuario, id_rol=@id_rol, activo=@activo WHERE id_usuario=@id", connection);
            cmdUser.Parameters.AddWithValue("@usuario", dto.usuario);
            cmdUser.Parameters.AddWithValue("@id_rol", dto.id_rol);
            cmdUser.Parameters.AddWithValue("@activo", dto.activo);
            cmdUser.Parameters.AddWithValue("@id", id);
            await cmdUser.ExecuteNonQueryAsync();

            // Si envió clave, actualizar
            if (!string.IsNullOrWhiteSpace(dto.clave))
            {
                var hashedPass = HashSHA256(dto.clave);
                var cmdPass = new SqlCommand("UPDATE TBL_USUARIO SET clave=@clave WHERE id_usuario=@id", connection);
                cmdPass.Parameters.AddWithValue("@clave", hashedPass);
                cmdPass.Parameters.AddWithValue("@id", id);
                await cmdPass.ExecuteNonQueryAsync();
            }

            // Si es TECNICO, upsert de relación supervisor-tecnico
            if (dto.rol.ToUpper() == "TECNICO")
            {
                var checkRel = new SqlCommand("SELECT COUNT(*) FROM TBL_SUPERVISOR_TECNICO WHERE id_tecnico=@id", connection);
                checkRel.Parameters.AddWithValue("@id", id);

                if ((int)await checkRel.ExecuteScalarAsync() > 0)
                {
                    var updateRel = new SqlCommand(
                        "UPDATE TBL_SUPERVISOR_TECNICO SET id_supervisor=@sup WHERE id_tecnico=@id", connection);
                    updateRel.Parameters.AddWithValue("@sup", dto.id_supervisor);
                    updateRel.Parameters.AddWithValue("@id", id);
                    await updateRel.ExecuteNonQueryAsync();
                }
                else
                {
                    var insertRel = new SqlCommand(
                        "INSERT INTO TBL_SUPERVISOR_TECNICO (id_supervisor, id_tecnico) VALUES (@sup, @id)", connection);
                    insertRel.Parameters.AddWithValue("@sup", dto.id_supervisor);
                    insertRel.Parameters.AddWithValue("@id", id);
                    await insertRel.ExecuteNonQueryAsync();
                }
            }

            return Results.Ok(new { message = "Usuario actualizado correctamente" });
        });

        // Inactivar usuario (baja lógica)
        app.MapDelete("/api/usuarios/{id:int}", async (int id) =>
        {
            var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

            using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync();

            var cmd = new SqlCommand("UPDATE TBL_USUARIO SET activo = 0 WHERE id_usuario = @id", connection);
            cmd.Parameters.AddWithValue("@id", id);

            int rows = await cmd.ExecuteNonQueryAsync();

            if (rows == 0)
                return Results.NotFound(new { message = "Usuario no encontrado" });

            return Results.Ok(new { message = "Usuario inactivado correctamente" });
        });

// POST /api/clientes (ADMINISTRADOR, SUPERVISOR)
app.MapPost("/api/clientes", async (HttpRequest request) =>
{
    var rol = request.Headers["rol"].ToString().ToUpper();
    if (!(rol == "ADMINISTRADOR" || rol == "SUPERVISOR")) return Results.Unauthorized();

    var dto = await request.ReadFromJsonAsync<ClienteDto>();
    if (dto == null || string.IsNullOrWhiteSpace(dto.nombre)) return Results.BadRequest(new { message = "Nombre requerido" });

    using var con = new SqlConnection(builder.Configuration.GetConnectionString("DefaultConnection"));
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

    var id = Convert.ToInt32(await cmd.ExecuteScalarAsync());
    return Results.Ok(new { message = "Cliente creado", id_cliente = id });
});

// PUT /api/clientes/{id} (ADMINISTRADOR, SUPERVISOR)
app.MapPut("/api/clientes/{id:int}", async (int id, HttpRequest request) =>
{
    var rol = request.Headers["rol"].ToString().ToUpper();
    if (!(rol == "ADMINISTRADOR" || rol == "SUPERVISOR")) return Results.Unauthorized();

    var dto = await request.ReadFromJsonAsync<ClienteUpdateDto>();
    if (dto == null) return Results.BadRequest();

    using var con = new SqlConnection(builder.Configuration.GetConnectionString("DefaultConnection"));
    await con.OpenAsync();

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

    var rows = await cmd.ExecuteNonQueryAsync();
    return rows > 0 ? Results.Ok(new { message = "Cliente actualizado" }) : Results.NotFound();
});

// DELETE /api/clientes/{id} (ADMINISTRADOR) → inactivar
app.MapDelete("/api/clientes/{id:int}", async (int id, HttpRequest request) =>
{
    var rol = request.Headers["rol"].ToString().ToUpper();
    if (rol != "ADMINISTRADOR") return Results.Unauthorized();

    using var con = new SqlConnection(builder.Configuration.GetConnectionString("DefaultConnection"));
    await con.OpenAsync();

    var cmd = new SqlCommand("UPDATE TBL_CLIENTES SET activo=0 WHERE id_cliente=@id", con);
    cmd.Parameters.AddWithValue("@id", id);

    var rows = await cmd.ExecuteNonQueryAsync();
    return rows > 0 ? Results.Ok(new { message = "Cliente inactivado" }) : Results.NotFound();
});
app.MapGet("/api/visitas/form-data", async (HttpRequest request) =>
{
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
    string supId = request.Query["supervisorId"]; // opcional

    using var cn = new SqlConnection(connectionString);
    await cn.OpenAsync();

    // Clientes
    var clientes = new List<object>();
    using (var cmd = new SqlCommand(@"SELECT id_cliente, nombre, direccion, coordenadas FROM TBL_CLIENTES WHERE activo = 1 ORDER BY nombre", cn))
    using (var rd = await cmd.ExecuteReaderAsync())
    {
        while (await rd.ReadAsync())
        {
            clientes.Add(new {
                id_cliente = rd.GetInt32(0),
                nombre = rd.GetString(1),
                direccion = rd.IsDBNull(2) ? null : rd.GetString(2),
                coordenadas = rd.IsDBNull(3) ? null : rd.GetString(3)
            });
        }
    }

    // Supervisores
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
            supervisores.Add(new {
                id_usuario = rd.GetInt32(0),
                usuario = rd.GetString(1),
                nombre = rd.GetString(2)
            });
        }
    }

    // Técnicos (si hay supervisorId, filtrar por relación)
    var tecnicos = new List<object>();
    string qTec = @"
        SELECT IU.id_usuario, U.usuario, IU.nombre
        FROM TBL_INFO_USUARIO IU
        INNER JOIN TBL_USUARIO U ON U.id_usuario = IU.id_usuario
        INNER JOIN TBL_ROL R ON R.id_rol = U.id_rol
        WHERE R.descripcion = 'TECNICO' AND U.activo = 1
        ORDER BY IU.nombre";

    if (!string.IsNullOrWhiteSpace(supId))
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
        if (!string.IsNullOrWhiteSpace(supId)) cmd.Parameters.AddWithValue("@idSup", int.Parse(supId));
        using var rd = await cmd.ExecuteReaderAsync();
        while (await rd.ReadAsync())
        {
            tecnicos.Add(new {
                id_usuario = rd.GetInt32(0),
                usuario = rd.GetString(1),
                nombre = rd.GetString(2)
            });
        }
    }

    return Results.Ok(new {
        clientes, supervisores, tecnicos
    });
});
app.MapGet("/api/visitas", async (HttpRequest request) =>
{
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

    string rol = request.Headers["rol"].ToString().ToUpper(); // ADMIN / SUP / TEC
    int idUsuario = int.Parse(request.Headers["id_usuario"]); // ID del usuario logueado

    var list = new List<object>();
    using var cn = new SqlConnection(connectionString);
    await cn.OpenAsync();

    var q = @"
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
    INNER JOIN TBL_USUARIO SU ON SU.id_usuario = V.id_supervisor
    INNER JOIN TBL_USUARIO TU ON TU.id_usuario = V.id_tecnico
    /**WHERE_CLAUSE**/
    ORDER BY V.id_visita DESC";

    string where = "";

    if (rol == "SUP") // Supervisor → solo visitas de sus técnicos asignados
    {
        where = @"
        WHERE V.id_tecnico IN (
            SELECT id_tecnico 
            FROM TBL_SUPERVISOR_TECNICO 
            WHERE id_supervisor = @idUsuario
        )";
    }
    else if (rol == "TEC") // Técnico → solo sus visitas
    {
        where = "WHERE V.id_tecnico = @idUsuario";
    }

    q = q.Replace("/**WHERE_CLAUSE**/", where);

    using var cmd = new SqlCommand(q, cn);
    cmd.Parameters.AddWithValue("@idUsuario", idUsuario);

    using var rd = await cmd.ExecuteReaderAsync();
    while (await rd.ReadAsync())
    {
        list.Add(new
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

    return Results.Ok(list);
});


app.MapPost("/api/visitas", async (VisitaCreateDto dto) =>
{
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

    using var cn = new SqlConnection(connectionString);
    await cn.OpenAsync();

    // Insertar visita
    var qIns = @"
      INSERT INTO TBL_VISITA (id_cliente, id_supervisor, id_tecnico, coordenadas_planificadas, fecha_visita)
      OUTPUT INSERTED.id_visita
      VALUES (@c, @s, @t, @coord, @f)";

    int idVisita;
    using (var cmd = new SqlCommand(qIns, cn))
    {
        cmd.Parameters.AddWithValue("@c", dto.id_cliente);
        cmd.Parameters.AddWithValue("@s", dto.id_supervisor);
        cmd.Parameters.AddWithValue("@t", dto.id_tecnico);
        cmd.Parameters.AddWithValue("@coord", dto.coordenadas_planificadas ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("@f", DateTime.Parse(dto.fecha_visita));
        idVisita = (int)await cmd.ExecuteScalarAsync();
    }

    // Obtener info para correo
    string clienteNom = "", clienteDir = "", clienteCoord = "", clienteMail = "";
    string tecnicoNom = "", tecnicoMail = "";

    // Cliente
    using (var cmd = new SqlCommand(@"
        SELECT nombre, direccion, coordenadas, correo
        FROM TBL_CLIENTES WHERE id_cliente=@c", cn))
    {
        cmd.Parameters.AddWithValue("@c", dto.id_cliente);
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
        WHERE U.id_usuario=@t", cn))
    {
        cmd.Parameters.AddWithValue("@t", dto.id_tecnico);
        using var rd = await cmd.ExecuteReaderAsync();
        if (await rd.ReadAsync())
        {
            tecnicoNom = rd.GetString(0);
            tecnicoMail = rd.IsDBNull(1) ? "" : rd.GetString(1);
        }
    }

    // ✅ Enviar correos de forma asíncrona
    Task.Run(() =>
    {
        try
        {
            var emailService = new SkynetApiAuth.Services.EmailService();
            emailService.SendVisitaAsignadaEmails(
                clienteMail,      // correo del cliente
                tecnicoMail,      // correo del técnico
                clienteNom,       // nombre del cliente
                clienteDir,       // dirección
                clienteCoord,     // coordenadas
                tecnicoNom,       // nombre técnico
                dto.fecha_visita  // fecha visita
            );
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error async email visita: " + ex.Message);
        }
    });

    return Results.Ok(new { message = "Visita creada", id_visita = idVisita });
});

app.MapPut("/api/visitas/{id:int}", async (int id, VisitaUpdateDto dto) =>
{
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

    using var cn = new SqlConnection(connectionString);
    await cn.OpenAsync();

    int oldTec = 0;
    using (var cmd = new SqlCommand("SELECT id_tecnico FROM TBL_VISITA WHERE id_visita=@id", cn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        var obj = await cmd.ExecuteScalarAsync();
        if (obj == null) return Results.NotFound(new { message="Visita no encontrada" });
        oldTec = Convert.ToInt32(obj);
    }

    var qUp = @"
      UPDATE TBL_VISITA
      SET id_cliente=@c, id_supervisor=@s, id_tecnico=@t, fecha_visita=@f, coordenadas_planificadas=@coord
      WHERE id_visita=@id";
    using (var cmd = new SqlCommand(qUp, cn))
    {
        cmd.Parameters.AddWithValue("@c", dto.id_cliente);
        cmd.Parameters.AddWithValue("@s", dto.id_supervisor);
        cmd.Parameters.AddWithValue("@t", dto.id_tecnico);
        cmd.Parameters.AddWithValue("@f", DateTime.Parse(dto.fecha_visita));
        cmd.Parameters.AddWithValue("@coord", dto.coordenadas_planificadas);
        cmd.Parameters.AddWithValue("@id", id);
        await cmd.ExecuteNonQueryAsync();
    }

    if (dto.id_tecnico != oldTec)
    {
        // reenvía SOLO al nuevo técnico
        string clienteNom="", clienteDir="", clienteCoord="";
        string tecnicoNom="", tecnicoUser="", tecnicoMail="";
        using (var cmd = new SqlCommand(@"
            SELECT C.nombre, C.direccion, C.coordenadas
            FROM TBL_CLIENTES C WHERE C.id_cliente=@c", cn))
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

        await EmailService.SendAvisoTecnicoReasignado(cn, new EmailVisitaData{
            IdVisita = id,
            ClienteNombre = clienteNom,
            ClienteDireccion = clienteDir,
            ClienteCoordenadas = clienteCoord,
            TecnicoNombre = tecnicoNom,
            TecnicoUsuario = tecnicoUser,
            TecnicoEmail = tecnicoMail,
            FechaVisita = DateTime.Parse(dto.fecha_visita),
            CoordenadasPlan = dto.coordenadas_planificadas
        });
    }

    return Results.Ok(new { message="Visita actualizada" });
});


app.MapGet("/api/usuarios/{id:int}/asignaciones", async (int id) =>
{
    var cs = builder.Configuration.GetConnectionString("DefaultConnection");

    using var cn = new SqlConnection(cs);
    await cn.OpenAsync();

    // Rol del usuario objetivo
    string tipo = "OTRO";
    using (var cmd = new SqlCommand(@"
        SELECT TOP 1 R.descripcion
        FROM TBL_USUARIO U
        INNER JOIN TBL_ROL R ON R.id_rol = U.id_rol
        WHERE U.id_usuario = @id", cn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        var rol = (string?)await cmd.ExecuteScalarAsync();
        if (!string.IsNullOrWhiteSpace(rol)) tipo = rol.ToUpper();
    }

    if (tipo == "SUPERVISOR")
    {
        // Técnicos asignados a este supervisor
        var list = new List<int>();
        using var cmd = new SqlCommand(@"
            SELECT id_tecnico
            FROM TBL_SUPERVISOR_TECNICO
            WHERE id_supervisor=@id
            ORDER BY id_tecnico", cn);
        cmd.Parameters.AddWithValue("@id", id);
        using var rd = await cmd.ExecuteReaderAsync();
        while (await rd.ReadAsync()) list.Add(rd.GetInt32(0));

        return Results.Ok(new {
            tipo = "SUPERVISOR",
            tecnicos_asignados = list,
            supervisor_asignado = (int?)null
        });
    }
    else if (tipo == "TECNICO")
    {
        // Supervisor del técnico (si existe)
        int? sup = null;
        using var cmd = new SqlCommand(@"
            SELECT TOP 1 id_supervisor
            FROM TBL_SUPERVISOR_TECNICO
            WHERE id_tecnico=@id", cn);
        cmd.Parameters.AddWithValue("@id", id);
        var obj = await cmd.ExecuteScalarAsync();
        if (obj != null && obj != DBNull.Value) sup = Convert.ToInt32(obj);

        return Results.Ok(new {
            tipo = "TECNICO",
            tecnicos_asignados = Array.Empty<int>(),
            supervisor_asignado = sup
        });
    }

    return Results.Ok(new {
        tipo = "OTRO",
        tecnicos_asignados = Array.Empty<int>(),
        supervisor_asignado = (int?)null
    });
});

// PUT /api/usuarios/{id}/asignaciones
// Solo ADMIN puede modificar.
// Payload según tipo:
//  - SUPERVISOR: { "tecnicos": [1,2,3] }
//  - TECNICO:    { "id_supervisor": 10 }
app.MapPut("/api/usuarios/{id:int}/asignaciones", async (int id, HttpRequest req) =>
{
    var cs = builder.Configuration.GetConnectionString("DefaultConnection");

    // Acepta tanto código como nombre
    var rolHdr = (req.Headers["rol"].ToString() ?? "").ToUpper();
    var rolNombreHdr = (req.Headers["rol_nombre"].ToString() ?? "").ToUpper();

    bool isAdmin =
        rolHdr == "ADMIN" ||
        rolNombreHdr == "ADMINISTRADOR";

    if (!isAdmin)
        return Results.Unauthorized();

    using var cn = new SqlConnection(cs);
    await cn.OpenAsync();

    // Tipo del usuario objetivo
    string tipo = "OTRO";
    using (var cmd = new SqlCommand(@"
        SELECT TOP 1 R.descripcion
        FROM TBL_USUARIO U
        INNER JOIN TBL_ROL R ON R.id_rol = U.id_rol
        WHERE U.id_usuario = @id", cn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        var rol = (string?)await cmd.ExecuteScalarAsync();
        if (!string.IsNullOrWhiteSpace(rol)) tipo = rol.ToUpper();
    }

    using var sr = new StreamReader(req.Body);
    var body = await sr.ReadToEndAsync();
    using var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(body) ? "{}" : body);
    var root = doc.RootElement;

    if (tipo == "SUPERVISOR")
    {
        // Reemplazo total de técnicos asignados
        var tec = new List<int>();
        if (root.TryGetProperty("tecnicos", out var arr) && arr.ValueKind == JsonValueKind.Array)
        {
            foreach (var x in arr.EnumerateArray())
                if (x.ValueKind == JsonValueKind.Number) tec.Add(x.GetInt32());
        }

        using var tx = cn.BeginTransaction();

        // Borra asignaciones actuales
        using (var del = new SqlCommand(@"DELETE FROM TBL_SUPERVISOR_TECNICO WHERE id_supervisor=@s", cn, tx))
        {
            del.Parameters.AddWithValue("@s", id);
            await del.ExecuteNonQueryAsync();
        }

        // Inserta nuevas
        if (tec.Count > 0)
        {
            foreach (var t in tec.Distinct())
            {
                using var ins = new SqlCommand(@"
                    INSERT INTO TBL_SUPERVISOR_TECNICO (id_supervisor, id_tecnico)
                    VALUES (@s, @t)", cn, tx);
                ins.Parameters.AddWithValue("@s", id);
                ins.Parameters.AddWithValue("@t", t);
                await ins.ExecuteNonQueryAsync();
            }
        }

        await tx.CommitAsync();
        return Results.Ok(new { message = "Asignaciones actualizadas (supervisor→técnicos)" });
    }
    else if (tipo == "TECNICO")
    {
        // Upsert de su supervisor
        int? idSup = null;
        if (root.TryGetProperty("id_supervisor", out var supEl) && supEl.ValueKind == JsonValueKind.Number)
            idSup = supEl.GetInt32();

        using var tx = cn.BeginTransaction();

        // Si no hay supervisor → elimina relación
        if (idSup is null)
        {
            using var del = new SqlCommand(@"DELETE FROM TBL_SUPERVISOR_TECNICO WHERE id_tecnico=@t", cn, tx);
            del.Parameters.AddWithValue("@t", id);
            await del.ExecuteNonQueryAsync();
            await tx.CommitAsync();
            return Results.Ok(new { message = "Supervisor desasignado del técnico" });
        }

        // Verificar si existe fila
        int count = 0;
        using (var chk = new SqlCommand(@"SELECT COUNT(*) FROM TBL_SUPERVISOR_TECNICO WHERE id_tecnico=@t", cn, tx))
        {
            chk.Parameters.AddWithValue("@t", id);
            count = Convert.ToInt32(await chk.ExecuteScalarAsync());
        }

        if (count > 0)
        {
            using var up = new SqlCommand(@"
                UPDATE TBL_SUPERVISOR_TECNICO SET id_supervisor=@s WHERE id_tecnico=@t", cn, tx);
            up.Parameters.AddWithValue("@s", idSup);
            up.Parameters.AddWithValue("@t", id);
            await up.ExecuteNonQueryAsync();
        }
        else
        {
            using var ins = new SqlCommand(@"
                INSERT INTO TBL_SUPERVISOR_TECNICO (id_supervisor, id_tecnico)
                VALUES (@s, @t)", cn, tx);
            ins.Parameters.AddWithValue("@s", idSup);
            ins.Parameters.AddWithValue("@t", id);
            await ins.ExecuteNonQueryAsync();
        }

        await tx.CommitAsync();
        return Results.Ok(new { message = "Supervisor asignado al técnico" });
    }

    return Results.BadRequest(new { message = "El usuario indicado no es SUPERVISOR ni TECNICO" });
});


app.MapPut("/api/supervisores/{id:int}/tecnicos", async (int id, HttpRequest request) =>
{
    var rol = request.Headers["rol"].ToString().ToUpper();
    if (rol != "ADMIN" && rol != "ADMINISTRADOR")
        return Results.Unauthorized();

    var body = await request.ReadFromJsonAsync<AsignarTecnicosDto>();
    if (body is null)
        return Results.BadRequest(new { message = "Datos inválidos" });

    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
    using var con = new SqlConnection(connectionString);
    await con.OpenAsync();

    using var tx = con.BeginTransaction();

    // 1. Borrar asignaciones actuales
    var del = new SqlCommand("DELETE FROM TBL_SUPERVISOR_TECNICO WHERE id_supervisor = @id", con, tx);
    del.Parameters.AddWithValue("@id", id);
    await del.ExecuteNonQueryAsync();

    // 2. Insertar nuevas asignaciones
    if (body.tecnicos != null && body.tecnicos.Count > 0)
    {
        foreach (var tecId in body.tecnicos.Distinct())
        {
            var ins = new SqlCommand(
                "INSERT INTO TBL_SUPERVISOR_TECNICO (id_supervisor, id_tecnico) VALUES (@sup, @tec)",
                con, tx
            );
            ins.Parameters.AddWithValue("@sup", id);
            ins.Parameters.AddWithValue("@tec", tecId);
            await ins.ExecuteNonQueryAsync();
        }
    }

    await tx.CommitAsync();
    return Results.Ok(new { message = "Asignaciones actualizadas correctamente", total = body.tecnicos?.Count ?? 0 });
});
        

        app.MapPost("/api/visitas/{id:int}/procesar", async (int id, ProcesarVisitaDto dto) =>
{
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

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
