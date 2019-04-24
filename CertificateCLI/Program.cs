using System;
using System.IO;
using System.Collections.Generic;
using CertificateAPI;
using Org.BouncyCastle.X509;

/*
 * This program is only used to test the CertificateAPI
 */

namespace CertificateCLI
{
    class MainClass
    {
        private static readonly string RSA_XML_PATH = "/RSA/";
        private static readonly string version = "0.0.1";

        private enum ExitCode {
            Success = 0,
            FailedParsingArgs = 1,
            UnknownError = 2,
        }

        /// <summary>
        /// Arguments used for the program.
        ///
        /// help and -h prints a help menu.
        /// generate will generate a CA cert and issue a cert with that CA with default name parameters.
        /// -in stands for issue name and -sn stands for subject name, these are the parameters you want to include if you want name your certs.
        /// -strength is used to determine the size of the RSA Key (Valid options are 2048-bits, 4096-bits and 8192-bits
        /// 
        /// Example usage:
        /// certcli generate -is "MLAPI Issuer" -sn "GameServer"
        /// certcli generate
        /// certcli help
        /// 
        /// </summary>
        private static readonly string[] arguments = {
            "help",
            "generate","-in", "-sn", "-strength",
            "version",
        };

        [Flags]
        private enum ArgFlags
        {
            None = 0, Generate = 1, IssuerName = 2, SubjectName = 4,
            Help = 8, Version = 16, View = 32, FileInput = 64,
        }


        public static int Main(string[] args)
        {
            //args = new string[] { "generate", "-in", "NSA Intermediate Cert", "-sn", "FRA Phishing Web server" };
            args = new string[] { "view", "-sn", "FRA Phishing Web server", "-f", "base64SubjectCert.txt" };
            //args = new string[] { "generate", "-in", "Let's Encrypt", "-sn", "A Server" };

            CertificateEmpire empire = null;

            if (args.Length == 0)
            {
                PrintHelp();
                return 1;
            }

            ArgFlags af = ArgFlags.None;

            foreach(string arg in args)
            {
                switch (arg)
                {
                    case "help":
                        Console.WriteLine("Help flag found");
                        if (af == ArgFlags.None)
                        {
                            af |= ArgFlags.Help;
                            Console.WriteLine("Help flag OR:ed.");
                        }
                        break;

                    case "version":
                        Console.WriteLine("Version flag found");
                        if (af == ArgFlags.None)
                        {
                            af |= ArgFlags.Version;
                            Console.WriteLine("Version flag OR:ed.");
                        }
                        break;

                    case "generate":
                        Console.WriteLine("Generate flag found");
                        if (af == ArgFlags.None)
                        {
                            af |= ArgFlags.Generate;
                            Console.WriteLine("Generate flag OR:ed.");
                        }
                        break;

                    case "-in":
                        Console.WriteLine("IssuerName flag found");
                        if(af == ArgFlags.Generate || af == (ArgFlags.Generate | ArgFlags.SubjectName))
                        {
                            af |= ArgFlags.IssuerName;
                            Console.WriteLine("IssuerName flag OR:ed.");
                        }
                        else if (af == ArgFlags.View || af == ArgFlags.FileInput)
                        {
                            af |= ArgFlags.IssuerName;
                            Console.WriteLine("IssuerName flag OR:ed.");
                        }

                        break;

                    case "-sn":
                        Console.WriteLine("Subject flag found");
                        if (af == ArgFlags.Generate || af == (ArgFlags.Generate | ArgFlags.IssuerName))
                        {
                            af |= ArgFlags.SubjectName;
                            Console.WriteLine("SubjectName flag OR:ed.");
                        }
                        else if (af == ArgFlags.View || af == ArgFlags.FileInput)
                        {
                            af |= ArgFlags.SubjectName;
                            Console.WriteLine("SubjectName flag OR:ed.");
                        }
                        break;

                    case "-f":
                        if (af.HasFlag(ArgFlags.View | ArgFlags.IssuerName) || af.HasFlag(ArgFlags.View | ArgFlags.SubjectName))
                        {
                            af |= ArgFlags.FileInput;
                            Console.WriteLine("FileInput flag OR:ed");
                        }
                        break;

                    case "view":
                        Console.WriteLine("View flag found");
                        if (af == ArgFlags.None)
                        {
                            af |= ArgFlags.View;
                            Console.WriteLine("View flag OR:ed.");
                        }
                        break;

                }
            }

            try
            {

                if (af.HasFlag(ArgFlags.Help))
                {
                    PrintHelp(false);
                }
                else if (af.HasFlag(ArgFlags.Version))
                {
                    PrintVersion();
                }
                else if (af.HasFlag(ArgFlags.Generate) && af.HasFlag(ArgFlags.IssuerName) && af.HasFlag(ArgFlags.SubjectName))
                {
                    Console.WriteLine("certcli: Generating certs with custom params ...");
                    empire = CertificateAPI.EmpireBuilder.Build($"CN={args[2]}", $"CN={args[4]}") as CertificateEmpire;
                }
                else if (af.HasFlag(ArgFlags.Generate))
                {
                    Console.WriteLine("certcli: Generating certs with default params ...");
                    empire = CertificateAPI.EmpireBuilder.Build("CN=Unnamed Issuer", "CN=Unnamed MLAPI Development Certificate") as CertificateEmpire;
                }
                else if (af.HasFlag(ArgFlags.View) && af.HasFlag(ArgFlags.FileInput) && (af.HasFlag(ArgFlags.IssuerName) || af.HasFlag(ArgFlags.SubjectName)))
                {
                    // Print base64
                    if (af.HasFlag(ArgFlags.IssuerName))
                        Console.WriteLine(PfxUtility.GetPfxFromBase64(args[4], $"CN={args[2]}").ToString());
                    else
                    {
                        if (File.Exists(args[4]))
                        {
                            using (var filestream = File.OpenRead(args[4]))
                            {
                                var buffer = new byte[filestream.Length];
                                filestream.Read(buffer, 0, (int)filestream.Length);
                                //Console.WriteLine(System.Text.Encoding.ASCII.GetString(buffer));
                                PrintCertificateFromBase64(buffer);
                            }
                        }
                        else
                            throw new FileNotFoundException();
                    }
                }

                else if (af.HasFlag(ArgFlags.View))
                {
                    Console.WriteLine("certcli: view usage:\n\t\t-[sn/in]: \"Name of subject\"\n\t\t-f: [file path]");
                }
                else
                {
                    PrintHelp(false);
                    return 1;
                }

            }
            catch(Exception e)
            {
                Console.WriteLine(e.Message);
                return 1;
            }

            if (empire != null)
            {
                using (var f = File.OpenWrite("issuer.cer")) 
                {
                    Console.WriteLine("Saving issuer certification as: issuer.cer");
                    var buffer = empire.Certs[0].GetEncoded();
                    f.Write(buffer, 0, buffer.Length);
                }

                using (var f = File.OpenWrite("subject.cer"))
                {
                    Console.WriteLine("Saving subject certification as: subject.cer");
                    var buffer =  empire.Certs[1].GetEncoded();
                    f.Write(buffer, 0, buffer.Length);
                }

                using (var f = File.OpenWrite("base64Pfx.txt"))
                {
                    Console.WriteLine("Pasting the base64 encoded PFX-container into base64.txt");
                    var buffer = System.Text.Encoding.ASCII.GetBytes(PfxUtility.ToPfxBase64(empire.Certs[0], empire.KeyPairs[0]));
                    f.Write(buffer, 0, buffer.Length);
                }

                using (var f = File.OpenWrite("base64SubjectCert.txt"))
                {
                    Console.WriteLine("Pasting the base64 encoded subject certificate into base64SubjectCert");
                    var buffer = System.Text.Encoding.ASCII.GetBytes(Convert.ToBase64String(empire.Certs[1].GetEncoded()));
                    f.Write(buffer, 0, buffer.Length);
                }



            }

            return 0;

        }

        public static void PrintHelp(bool zeroParams = true)
        {
            if(zeroParams)
                Console.WriteLine("certcli:\t\tZero params found!\n\t\tUsage: certcli [help] [version] [generate] <command> [<args>]");
            else
                Console.WriteLine("Usage: certcli [help] [version] [generate] <command> [<args>]");

        }

        public static void PrintVersion()
        {
            Console.WriteLine(version);
        }

        public static void PrintCertificateFromBase64(byte[] b64)
        {
            // FRom base64 in byte to baes64 string
            X509Certificate cert = new X509CertificateParser().ReadCertificate(Convert.FromBase64String(System.Text.Encoding.ASCII.GetString(b64)));
            Console.WriteLine(cert.ToString());
        }

    }


}
