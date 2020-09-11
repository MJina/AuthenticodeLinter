using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AuthenticodeExaminer;


namespace AuthenticodeLinter.Tests
{
    public class CriticalKeyUsageExtensionTest : IAuthenticodeSignatureTest
    {
        public int Test => 10009;

        public string TestName => "Critical Key Usage Extension";

        public string ShortDescription => "Check if key usage extension is marked critical.";

        public TestSet TestSet => TestSet.All;

        public TestResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var signatures = graph.VisitAll(SignatureKind.AnySignature);
            var pass = false;
            foreach (var signature in signatures)
            {
                string serialNumber = "";
                string KU = "";
                Boolean KUCritical = false;
                int KU_extension = 0;

                string thumbprint = signature.Certificate.Thumbprint;
                serialNumber = signature.Certificate.SerialNumber;
                X509ExtensionCollection extensions = signature.Certificate.Extensions;
                foreach (X509Extension extension in extensions)
                {
                    //extension.Oid.FriendlyName
                    Console.WriteLine(extension.Oid.FriendlyName + "(" + extension.Oid.Value + ")");


                    if (extension.Oid.FriendlyName == "Key Usage")
                    {
                        X509KeyUsageExtension ext = (X509KeyUsageExtension)extension;
                        KUCritical = ext.Critical;
                        KU = ext.KeyUsages.ToString();
                        Console.WriteLine(KU);
                        KU_extension++;
                    }            
                }

                if (KU_extension == 1)
                {
                    if (KUCritical)
                    {
                        verboseWriter.LogSignatureMessage(signature, "Key Usage extension is marked critical.");
                        pass = true;
                    }
                    else
                    {
                        verboseWriter.LogSignatureMessage(signature, "Key Usage extension is not marked critical.");
                        pass = false;
                    }
                }
                else if (KU_extension == 0)
                {
                    verboseWriter.LogSignatureMessage(signature, "Signature does not have Key Usage extension.");
                    pass = false;
                }
                else if (KU_extension > 1)
                {
                    verboseWriter.LogSignatureMessage(signature, "Signature has duplicate Key Usage extension.");
                    pass = false;
                }
            }

            return pass ? TestResult.Pass : TestResult.Fail;
        }
    }
}
