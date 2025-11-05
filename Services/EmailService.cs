using System.Net;
using System.Net.Mail;

namespace SkynetApiAuth.Services
{
    public class EmailService
    {
        private readonly string _from = "skynetsa2513@gmail.com";
        private readonly string _fromName = "SkyNet System";
        private readonly string _appPassword = "bfdu bqzf qtle eklf"; // App password Gmail

        private SmtpClient GetSmtp()
        {
            return new SmtpClient("smtp.gmail.com")
            {
                Port = 587,
                Credentials = new NetworkCredential(_from, _appPassword),
                EnableSsl = true
            };
        }

        // ✅ Enviar credenciales de nuevo usuario
        public void SendUserCredentials(string correoDestino, string usuario, string clave, string rol, string nombre)
        {
            try
            {
                var mail = new MailMessage
                {
                    From = new MailAddress(_from, _fromName),
                    Subject = "Credenciales de Acceso - SkyNet",
                    Body = $@"
Hola {nombre},

Se ha creado tu usuario para el sistema SkyNet.

👤 Usuario: {usuario}
🔑 Contraseña: {clave}
🧬 Rol asignado: {rol}

Por motivos de seguridad, te recomendamos cambiar tu contraseña al iniciar sesión.

Saludos,
SkyNet System
",
                    IsBodyHtml = false
                };

                mail.To.Add(correoDestino);

                GetSmtp().Send(mail);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error enviando correo de credenciales: " + ex.Message);
            }
        }

        // ✅ Enviar correos de visita asignada
        public void SendVisitaAsignadaEmails(
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
                string coordenadasText = string.IsNullOrWhiteSpace(coords) ? "No registradas" : coords;

                // ---- Técnico ----
                if (!string.IsNullOrWhiteSpace(correoTecnico))
                {
                    var mailTec = new MailMessage
                    {
                        From = new MailAddress(_from, _fromName),
                        Subject = "Nueva Visita Asignada - SkyNet - Tecico",
                        Body = $@"
Hola {tecnico},

Se te ha asignado una nueva visita.

📍 Cliente: {cliente}
🏠 Dirección: {direccion}
🗓 Fecha: {fechaVisita}
📌 Coordenadas: {coordenadasText}

Por favor revisa los detalles y prepárate para la visita.

SkyNet System
",
                        IsBodyHtml = false
                    };

                    mailTec.To.Add(correoTecnico);
                    GetSmtp().Send(mailTec);
                }

                // ---- Cliente ----
                if (!string.IsNullOrWhiteSpace(correoCliente))
                {
                    var mailCli = new MailMessage
                    {
                        From = new MailAddress(_from, _fromName),
                        Subject = "Visita Programada - SkyNet -Cliente",
                        Body = $@"
Hola {cliente},

Hemos programado una visita para su atención.

🧑‍🔧 Técnico asignado: {tecnico}
🗓 Fecha: {fechaVisita}
🏠 Dirección: {direccion}
📌 Coordenadas: {coordenadasText}

Gracias por preferir nuestros servicios.

SkyNet System
",
                        IsBodyHtml = false
                    };

                    mailCli.To.Add(correoCliente);
                    GetSmtp().Send(mailCli);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error enviando correos de visita: " + ex.Message);
            }
        }

// ✅ Enviar correos cuando la visita es procesada (atendida)
public void SendVisitaProcesadaEmail(
    string correoCliente,
    string correoSupervisor,
    string tecnico,
    string fechaAtencion,
    string coordenadasFinales
)
{
    try
    {
        string coordsText = string.IsNullOrWhiteSpace(coordenadasFinales) ? "No registradas" : coordenadasFinales;

        // ---- Correo al Cliente con copia al Supervisor ----
        if (!string.IsNullOrWhiteSpace(correoCliente))
        {
            var mailCli = new MailMessage
            {
                From = new MailAddress(_from, _fromName),
                Subject = "Visita Atendida - SkyNet",
                Body = $@"
Estimado cliente,

Le informamos que la visita asignada ha sido atendida.

🧑‍🔧 Técnico que lo atendió: {tecnico}
📅 Fecha de atención: {fechaAtencion}
📍 Coordenadas de atención: {coordsText}

Gracias por permitirnos servirle,
SkyNet System
",
                IsBodyHtml = false
            };

            mailCli.To.Add(correoCliente);

            if (!string.IsNullOrWhiteSpace(correoSupervisor))
                mailCli.CC.Add(correoSupervisor);

            GetSmtp().Send(mailCli);
        }
        else if (!string.IsNullOrWhiteSpace(correoSupervisor))
        {
            // Si el cliente no tiene correo, enviar solo al supervisor
            var mailSup = new MailMessage
            {
                From = new MailAddress(_from, _fromName),
                Subject = "Visita Atendida - Informe SkyNet",
                Body = $@"
Se atendió la visita asignada.

🧑‍🔧 Técnico que realizó la atención: {tecnico}
📅 Fecha de atención: {fechaAtencion}
📍 Coordenadas de atención: {coordsText}

Saludos,
SkyNet System
",
                IsBodyHtml = false
            };

            mailSup.To.Add(correoSupervisor);
            GetSmtp().Send(mailSup);
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine("Error enviando correo de visita procesada: " + ex.Message);
    }
}

// ✅ Enviar correo cuando la visita fue procesada
public void SendVisitaProcesadaEmail(
    string correoCliente,
    string correoSupervisor,
    string cliente,
    string tecnico,
    string coordenadas,
    string fechaAtencion
)
{
    string coordsText = string.IsNullOrWhiteSpace(coordenadas) ? "No registradas" : coordenadas;

    try
    {
        // 📩 Email para el Cliente
        if (!string.IsNullOrWhiteSpace(correoCliente))
        {
            var mailCli = new MailMessage
            {
                From = new MailAddress(_from, _fromName),
                Subject = "Visita Atendida - SkyNet",
                Body = $@"
Hola {cliente},

Su visita ha sido atendida satisfactoriamente.

🧑‍🔧 Técnico que lo atendió: {tecnico}
📍 Coordenadas de atención: {coordsText}
📅 Fecha y hora de atención: {fechaAtencion}

Gracias por confiar en nuestros servicios.
SkyNet System
",
                IsBodyHtml = false
            };

            mailCli.To.Add(correoCliente);
            GetSmtp().Send(mailCli);
        }

        // 📩 Copia al Supervisor
        if (!string.IsNullOrWhiteSpace(correoSupervisor))
        {
            var mailSup = new MailMessage
            {
                From = new MailAddress(_from, _fromName),
                Subject = "Visita Atendida - Información",
                Body = $@"
Hola,

Se ha completado una visita asignada a uno de sus técnicos.

🧑‍🔧 Técnico: {tecnico}
👤 Cliente: {cliente}
📍 Coordenadas de atención: {coordsText}
📅 Fecha y hora: {fechaAtencion}

SkyNet System
",
                IsBodyHtml = false
            };

            mailSup.To.Add(correoSupervisor);
            GetSmtp().Send(mailSup);
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine("❌ Error enviando correos de visita procesada: " + ex.Message);
    }
}






    }
}
