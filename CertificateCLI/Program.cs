using System;
using System.IO;
using System.Collections.Generic;
using CertificateAPI;

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
            //args = new string[] { "generate", "-in", "Let's Encrypt", "-sn", "A Server" };
            args = new string[] { "view", "-f", "CN=Unnamed Issuer", "MIID/AIBAzCCA8IGCSqGSIb3DQEHAaCCA7MEggOvMIIDqzCCA6cGCSqGSIb3DQEHBqCCA5gwggOUAgEAMIIDjQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIb94cfT4YxVkCAggAgIIDYKOeZcT2L1Av3qlq/kDEGyGjY04CE1lrU0uv3RZ34Gg9TLE6J7nvcT25b9uKdE9rmStJPqdr7qUsukRGWMemHKIRnRGmcL3B2QDM0t8brYvSrQwZNDi8wfYj+wIQ01i44BfliIrqUMLD4tU4/eBiPzXy3TboBuc7b/p7fVB6zwLju0YJkOkCJREAh6PAj2xoSP65mM4LU5tyzeCovY3xlri5ogcjWxPfyNpvnncqqlaTlYfKLMjkqDFTaI/sdIvRcghJryhppiKExOmVxOSTCaOwcx4WoAmDmEplz968y/qT8pkymgpcVT+e+xbly9wHRxUnezMN86w/1XIODyON7CtNQejEBVQ0x3I5pPQk9my/mdA5N91lU8ykQ1cLo8O/iQb6MmD4GQJISe/LrmWtglYXfWkh8iwW8YEG3PMnoUPzrx6bEfUWvDHGEJxZEpv0YhPJK4fdVltah0vD9p1uq9MiAcYxjDpk3KOyDYqI8aMe2YBOR90rhzwtxYEDaM1hgju2tT93yW23EhO5VeclvbztRqhlrK3nQ0VKy/B+Gey14dKUdmrqECXx8vUzBUhKj5xG3muk1sIMlxDHrm2O6GMAn6o91e6SOrOTE6UU/ZuQze2EVBTjRci2r7XuVt3dtAv+UmL+zVXgiQ0Zvn8kHnBI6gQQ3DXwze8INvGOEPPNuRT8D7XA6xDpLJMhIFwN7yXntvRC4/gA1NiAlPkNTBmWu5iVXNF2cVzclkEWv2Jr2zrlJXzxiF6D73Qs+Gy8bbVBr0jlc/DPkkVBOzWEaL6bR7K9KB4aTLXRnlpuM457tmDASccIoDuT0F6iWX59t7C1qLQyT04puBGzQ9wMwA0vmuU/vb3urzwlnKNcVWwxWth740FvkwdJDPoLTST0A6jt+i8PSk4QwUddDEb3V03EVdt5eG7bzrbCLQ+mXJZM7sZoQVml8BrDcWIAzSuUCz/bzHB7bqOXNRUrMwXdi7uWDzmyX47M4GgDz1jHaXQYBhr1sfSXDaEYfIwNtPb36bv4UP+O6FzkthDyJpPsOgu1FStVubiFEnDCI0bbK7KzpIvPVD5NIyHn/psT3ZoxJtC4GA5nhUaLqzOGAUZmUs2TNDqkoHHbXZxauOOcv3Q/ra6HjuJYYCTbTD50p9kxlzAxMCEwCQYFKw4DAhoFAAQUMPE/Pmm2s/lTfX8dKFMck8XTA8wECJNTFwglC8YMAgIIAA==" };
            //args = new string[] { "generate", "-in", "Let's Encrypt", "-sn", "A Server" };

            CertificateEmpire? empire = null;

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
                        break;

                    case "-sn":
                        Console.WriteLine("Subject flag found");
                        if (af == ArgFlags.Generate || af == (ArgFlags.Generate | ArgFlags.IssuerName))
                        {
                            af |= ArgFlags.SubjectName;
                            Console.WriteLine("SubjectName flag OR:ed.");
                        }
                        break;

                    case "-f":
                        if (af == ArgFlags.View)
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
                else if (af.HasFlag(ArgFlags.Generate))
                {
                    Console.WriteLine("certcli: Generating certs with default params ...");
                    empire = CertificateAPI.CertGenerator.GenerateEmpire("CN=Unnamed Issuer", "CN=Unnamed MLAPI Development Certificate");
                }
                else if (af.HasFlag(ArgFlags.View & ArgFlags.FileInput))
                {
                    // Print base64
                    CertificateAPI.Pfx.GetPfxBase64(args[3], args[2]);
                }
                else if (af.HasFlag(ArgFlags.Generate & ArgFlags.IssuerName & ArgFlags.SubjectName))
                {
                    Console.WriteLine("certcli: Generating certs with custom params ...");
                    empire = CertificateAPI.CertGenerator.GenerateEmpire($"CN={args[2]}", $"CN={args[4]}");
                }
                else if (af.HasFlag(ArgFlags.View))
                {
                    Console.WriteLine("certcli: use the -f parameter with a file path");
                }
                else
                {

                }

            }
            catch(Exception e)
            {
                Console.WriteLine(e.Message);
                return 1;
            }

            if (empire != null)
            {
                Console.WriteLine($"{empire.Value.ToString()}");

                using (var f = File.OpenWrite("issuer.cer")) {
                    var buffer = empire.Value.issuerCertificate.GetEncoded();
                    f.Write(buffer, 0, buffer.Length);
                }

                using (var f = File.OpenWrite("subject.cer"))
                {
                    var buffer = empire.Value.subjectCertificate.GetEncoded();
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

        public static void PrintPfx(string b64)
        {

        }

    }


}
