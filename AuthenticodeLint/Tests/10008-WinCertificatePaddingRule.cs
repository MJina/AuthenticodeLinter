using System;
using System.Linq;
using System.Numerics;

namespace AuthenticodeLinter.Tests
{
    public class WinCertificatePaddingTest : IAuthenticodeFileTest
    {
        public int Test => 10008;

        public string TestName => "No WinCertificate Structure Padding";

        public string ShortDescription => "Checks for non-zero data after the signature.";

        public TestSet TestSet => TestSet.All;

        public TestResult Validate(string file, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var padding = CertificatePaddingExtractor.ExtractPadding(file);
            if (padding?.Any(p => p != 0) == true)
            {
                verboseWriter.LogMessage($"Non-zero data found after PKCS#7 structure: {Convert.ToBase64String(padding)}.");
                return TestResult.Fail;
            }
            return TestResult.Pass;
        }
    }
}
