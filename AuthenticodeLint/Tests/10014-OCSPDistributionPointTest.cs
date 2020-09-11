using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AuthenticodeExaminer;


namespace AuthenticodeLinter.Tests
{
    public class OCSPDistributionPointTest : IAuthenticodeSignatureTest
    {
        public int Test => 10014;

        public string TestName => "OCSP Distribution Point Test";

        public string ShortDescription => "Check if signature provides OCSP distribution point.";

        public TestSet TestSet => TestSet.All;

        public TestResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var signatures = graph.VisitAll(SignatureKind.AnySignature);
            int AIA_extension = 0;
            Boolean AIACritical = false;
            string authorityInformationAccess = "";
            var pass = false;
            foreach (var signature in signatures)
            {
                string serialNumber = "";
                AIA_extension = 0;
                AIACritical = false;
                authorityInformationAccess = "";

                string thumbprint = signature.Certificate.Thumbprint;
                var digestStr = HashHelpers.GetHashForSignature(signature);//message digest of siganture(signature->details->advance->msg digest)
                serialNumber = signature.Certificate.SerialNumber;
                X509ExtensionCollection extensions = signature.Certificate.Extensions;
                foreach (X509Extension extension in extensions)
                {
                    /*This extension MUST be present and MUST NOT be marked critical. 
                     * The extension MUST contain the HTTP URL of the CA’s OCSP responder (accessMethod = 1.3.6.1.5.5.7.48.1) 
                     * and the HTTP URL for the Root CA’s certificate (accessMethod = 1.3.6.1.5.5.7.48.2).*/

                    if (extension.Oid.FriendlyName == "Authority Information Access")
                    {
                        if (AIA_extension != 0)
                        {
                            authorityInformationAccess = extension.Format(true);
                            AIACritical = extension.Critical;
                        }
                        Console.WriteLine(authorityInformationAccess);
                    }

                }

                if (authorityInformationAccess != "" && authorityInformationAccess.Contains("http://") && !AIACritical)
                {
                    verboseWriter.LogSignatureMessage(signature, "Signature has properly provided OCSP distribution point.");
                    pass = true;
                }
                else
                {
                    verboseWriter.LogSignatureMessage(signature, "Signature has not properly provided OCSP distribution point.");
                    pass = false;
                }
            }

            return pass ? TestResult.Pass : TestResult.Fail;
        }
    }
}
