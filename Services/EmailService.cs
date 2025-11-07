using SendGrid;
using SendGrid.Helpers.Mail;

namespace SkynetApiAuth.Services
{
    public class EmailService
    {
        private readonly string _from = "jmoranv3@miumg.edu.gt";
        private readonly string _fromName = "SkyNet System";

        private SendGridClient GetClient()
        {
            var apiKey = Environment.GetEnvironmentVariable("SENDGRID_API_KEY");
            if (string.IsNullOrWhiteSpace(apiKey))
                throw new Exception("❌ No se encontró la variable de entorno SENDGRID_API_KEY.");

            return new SendGridClient(apiKey);
        }

        // ✅ Enviar credenciales de nuevo usuario
        public async Task SendUserCredentialsAsync(string correoDestino, string usuario, string clave, string rol, string nombre)
        {
            try


            {
                 Console.WriteLine(correoDestino);
                var client = GetClient();
                var from = new EmailAddress(_from, _fromName);
                var to = new EmailAddress(correoDestino);
                var subject = "Credenciales de Acceso - SkyNet";

                var body = $@"
Hola {nombre},

Se ha creado tu usuario para el sistema SkyNet.

👤 Usuario: {usuario}
🔑 Contraseña: {clave}
🧬 Rol asignado: {rol}

Por motivos de seguridad, te recomendamos cambiar tu contraseña al iniciar sesión.

Saludos,
SkyNet System
";

                var msg = MailHelper.CreateSingleEmail(from, to, subject, body, null);
                await client.SendEmailAsync(msg);
                Console.WriteLine($"✅ Correo enviado a {correoDestino} ({rol})");
            }
            catch (Exception ex)
            {
                Console.WriteLine("❌ Error enviando correo de credenciales: " + ex.Message);
            }
        }

        // ✅ Enviar correos de visita asignada
        public async Task SendVisitaAsignadaEmailsAsync(
            string correoCliente,
            string correoTecnico,
            string cliente,
            string direccion,
            string coords,
            string tecnico,
            string fechaVisita
        )
        {
            try
            {
                var client = GetClient();
                string coordenadasText = string.IsNullOrWhiteSpace(coords) ? "No registradas" : coords;
                var from = new EmailAddress(_from, _fromName);

                // ---- Técnico ----
                if (!string.IsNullOrWhiteSpace(correoTecnico))
                {
                    var toTec = new EmailAddress(correoTecnico);
                    var subjectTec = "Nueva Visita Asignada - SkyNet (Técnico)";
                    var bodyTec = $@"
Hola {tecnico},

Se te ha asignado una nueva visita.

📍 Cliente: {cliente}
🏠 Dirección: {direccion}
🗓 Fecha: {fechaVisita}
📌 Coordenadas: {coordenadasText}

Por favor revisa los detalles y prepárate para la visita.

SkyNet System
";
                    var msgTec = MailHelper.CreateSingleEmail(from, toTec, subjectTec, bodyTec, null);
                    await client.SendEmailAsync(msgTec);
                }

                // ---- Cliente ----
                if (!string.IsNullOrWhiteSpace(correoCliente))
                {
                    var toCli = new EmailAddress(correoCliente);
                    var subjectCli = "Visita Programada - SkyNet";
                    var bodyCli = $@"
Hola {cliente},

Hemos programado una visita para su atención.

🧑‍🔧 Técnico asignado: {tecnico}
🗓 Fecha: {fechaVisita}
🏠 Dirección: {direccion}
📌 Coordenadas: {coordenadasText}

Gracias por preferir nuestros servicios.

SkyNet System
";
                    var msgCli = MailHelper.CreateSingleEmail(from, toCli, subjectCli, bodyCli, null);
                    await client.SendEmailAsync(msgCli);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("❌ Error enviando correos de visita asignada: " + ex.Message);
            }
        }

        // ✅ Enviar correos cuando la visita es procesada (atendida)
        public async Task SendVisitaProcesadaEmailAsync(
            string correoCliente,
            string correoSupervisor,
            string tecnico,
            string fechaAtencion,
            string coordenadasFinales
        )
        {
            try
            {
                var client = GetClient();
                var from = new EmailAddress(_from, _fromName);
                string coordsText = string.IsNullOrWhiteSpace(coordenadasFinales) ? "No registradas" : coordenadasFinales;

                // ---- Cliente ----
                if (!string.IsNullOrWhiteSpace(correoCliente))
                {
                    var toCli = new EmailAddress(correoCliente);
                    var subjectCli = "Visita Atendida - SkyNet";
                    var bodyCli = $@"
Estimado cliente,

Le informamos que la visita asignada ha sido atendida.

🧑‍🔧 Técnico que lo atendió: {tecnico}
📅 Fecha de atención: {fechaAtencion}
📍 Coordenadas de atención: {coordsText}

Gracias por permitirnos servirle,
SkyNet System
";
                    var msgCli = MailHelper.CreateSingleEmail(from, toCli, subjectCli, bodyCli, null);

                    // Copia al supervisor
                    if (!string.IsNullOrWhiteSpace(correoSupervisor))
                        msgCli.AddCc(new EmailAddress(correoSupervisor));

                    await client.SendEmailAsync(msgCli);
                }
                else if (!string.IsNullOrWhiteSpace(correoSupervisor))
                {
                    // Solo al supervisor si el cliente no tiene correo
                    var toSup = new EmailAddress(correoSupervisor);
                    var subjectSup = "Visita Atendida - Informe SkyNet";
                    var bodySup = $@"
Se atendió la visita asignada.

🧑‍🔧 Técnico: {tecnico}
📅 Fecha de atención: {fechaAtencion}
📍 Coordenadas: {coordsText}

SkyNet System
";
                    var msgSup = MailHelper.CreateSingleEmail(from, toSup, subjectSup, bodySup, null);
                    await client.SendEmailAsync(msgSup);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("❌ Error enviando correo de visita procesada: " + ex.Message);
            }
        }

        // ✅ Versión extendida: correo al cliente y supervisor
        public async Task SendVisitaProcesadaEmailAsync(
            string correoCliente,
            string correoSupervisor,
            string cliente,
            string tecnico,
            string coordenadas,
            string fechaAtencion
        )
        {
            try
            {
                var client = GetClient();
                var from = new EmailAddress(_from, _fromName);
                string coordsText = string.IsNullOrWhiteSpace(coordenadas) ? "No registradas" : coordenadas;

                // ---- Cliente ----
                if (!string.IsNullOrWhiteSpace(correoCliente))
                {
                    var toCli = new EmailAddress(correoCliente);
                    var subjectCli = "Visita Atendida - SkyNet";
                    var bodyCli = $@"
Hola {cliente},

Su visita ha sido atendida satisfactoriamente.

🧑‍🔧 Técnico que lo atendió: {tecnico}
📍 Coordenadas de atención: {coordsText}
📅 Fecha y hora: {fechaAtencion}

Gracias por confiar en nuestros servicios.
SkyNet System
";
                    var msgCli = MailHelper.CreateSingleEmail(from, toCli, subjectCli, bodyCli, null);
                    await client.SendEmailAsync(msgCli);
                }

                // ---- Supervisor ----
                if (!string.IsNullOrWhiteSpace(correoSupervisor))
                {
                    var toSup = new EmailAddress(correoSupervisor);
                    var subjectSup = "Visita Atendida - Información SkyNet";
                    var bodySup = $@"
Hola,

Se ha completado una visita asignada a uno de sus técnicos.

🧑‍🔧 Técnico: {tecnico}
👤 Cliente: {cliente}
📍 Coordenadas: {coordsText}
📅 Fecha y hora: {fechaAtencion}

SkyNet System
";
                    var msgSup = MailHelper.CreateSingleEmail(from, toSup, subjectSup, bodySup, null);
                    await client.SendEmailAsync(msgSup);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("❌ Error enviando correos de visita procesada: " + ex.Message);
            }
        }
    }
}
