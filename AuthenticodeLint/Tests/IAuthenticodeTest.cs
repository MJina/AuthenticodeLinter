using AuthenticodeExaminer;
using System.Collections.Generic;

namespace AuthenticodeLinter.Tests
{
    public interface IAuthenticodeTest
    {
        int Test { get; }
        string ShortDescription { get; }
        string TestName { get; }
        TestSet TestSet { get; }
    }

    public interface IAuthenticodeSignatureTest : IAuthenticodeTest
    {
        TestResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration);
    }

    public interface IAuthenticodeFileTest : IAuthenticodeTest
    {
        TestResult Validate(string file, SignatureLogger verboseWriter, CheckConfiguration configuration);
    }
}
