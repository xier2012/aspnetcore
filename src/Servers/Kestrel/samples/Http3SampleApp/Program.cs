using System;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Http3SampleApp
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // TODO resolve x509 cert in config
            var certName = "netcorehttp3.westus2.cloudapp.azure.com";
            if (args.Length > 0)
            {
                certName = args[0];
            }

            var cert = CertificateLoader.LoadFromStoreCert(certName, StoreName.My.ToString(), StoreLocation.LocalMachine, true);
            var hostBuilder = new HostBuilder()
                 .ConfigureLogging((_, factory) =>
                 {
                     factory.SetMinimumLevel(LogLevel.Trace);
                     factory.AddConsole();
                 })
                 .ConfigureWebHost(webHost =>
                 {
                     webHost.UseKestrel()
                     // Things like APLN and cert should be able to be passed from corefx into bedrock
                     .UseQuic(options =>
                     {
                         options.Certificate = cert;
                         options.RegistrationName = "Quic";
                         options.Alpn = "h3-25";
                         options.IdleTimeout = TimeSpan.FromHours(1);
                     })
                     .ConfigureKestrel((context, options) =>
                     {
                         var basePort = 443;
                         options.EnableAltSvc = true;
                         options.Listen(IPAddress.Any, basePort, listenOptions =>
                         {
                             listenOptions.UseHttps(httpsOptions =>
                             {
                                 httpsOptions.ServerCertificate = cert;
                             });
                         });
                         options.Listen(IPAddress.Any, basePort, listenOptions =>
                         {
                            listenOptions.UseHttps(httpsOptions =>
                             {
                                 httpsOptions.ServerCertificate = cert;
                             });
                            listenOptions.Protocols = HttpProtocols.Http3;
                         });
                     })
                     .UseStartup<Startup>();
                 });

            hostBuilder.Build().Run();
        }
    }
}
