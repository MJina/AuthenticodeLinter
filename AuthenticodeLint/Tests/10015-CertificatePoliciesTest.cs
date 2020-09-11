using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AuthenticodeExaminer;


namespace AuthenticodeLinter.Tests
{
    public class CertificatePoliciesTest : IAuthenticodeSignatureTest
    {
        public int Test => 10015;

        public string TestName => "Certificate policies Extension";

        public string ShortDescription => "Check if certificate policies extension is present.";

        public TestSet TestSet => TestSet.All;

        public TestResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var signatures = graph.VisitAll(SignatureKind.AnySignature);
            var pass = false;
            foreach (var signature in signatures)
            {
                string serialNumber = "";

                string certificatePolicies = "";
                Boolean CPCritical = false;
                int certificatePolicies_extension = 0;

                string thumbprint = signature.Certificate.Thumbprint;
                serialNumber = signature.Certificate.SerialNumber;
                X509ExtensionCollection extensions = signature.Certificate.Extensions;
                foreach (X509Extension extension in extensions)
                {
                    //extension.Oid.FriendlyName
                    Console.WriteLine(extension.Oid.FriendlyName + "(" + extension.Oid.Value + ")");


                    if (extension.Oid.FriendlyName == "Certificate Policies")
                    {
                        certificatePolicies_extension = 1;
                        certificatePolicies = extension.Format(true);
                        CPCritical = extension.Critical;
                        Console.WriteLine(certificatePolicies);
                    }
                }

                if (certificatePolicies_extension == 1)
                {
                        verboseWriter.LogSignatureMessage(signature, "has certificate policies extension.");
                        pass = true;
                }
                else
                {
                        verboseWriter.LogSignatureMessage(signature, "does not have certificate policies extension.");
                        pass = false;
                }
                
            }

            return pass ? TestResult.Pass : TestResult.Fail;
        }
    }
}
