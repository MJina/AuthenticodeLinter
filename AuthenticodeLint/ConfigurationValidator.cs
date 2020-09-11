using AuthenticodeExaminer;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace AuthenticodeLinter
{
    public class CheckConfiguration
    {
        public IReadOnlyList<string> InputPaths { get; }
        public string ReportPath { get; }
        public bool Quiet { get; }
        public HashSet<int> SuppressErrorIDs { get; }
        public bool Verbose { get; }
        public RevocationChecking RevocationMode {get;}
        public string ExtractPath { get; }
        public TestSet TestSet { get; }

        public CheckConfiguration(IReadOnlyList<string> inputPaths, string reportPath, bool quiet, HashSet<int> suppressErrorIDs, bool verbose, RevocationChecking revocationMode, string extract, TestSet testSet)
        {
            InputPaths = inputPaths;
            ReportPath = reportPath;
            Quiet = quiet;
            SuppressErrorIDs = suppressErrorIDs;
            Verbose = verbose;
            RevocationMode = revocationMode;
            ExtractPath = extract;
            TestSet = testSet;
        }
    }

    public static class ConfigurationValidator
    {
        //Does its best to validate the configuration, such as the path actually existing, etc.
        public static bool ValidateAndPrint(CheckConfiguration configuration, TextWriter printer)
        {
            bool success = true;
            if (configuration.Verbose && configuration.Quiet)
            {
                printer.WriteLine("Cannot combine verbose and quiet configuration.");
                success = false;
            }
            foreach (var path in configuration.InputPaths)
            {
                if (!File.Exists(path))
                {
                    printer.WriteLine($"The input path {path} does not exist.");
                    success = false;
                }
            }
            var tests = CheckEngine.Instance.GetTests();
            foreach (var suppression in configuration.SuppressErrorIDs)
            {
                if (!tests.Any(r => r.Test == suppression))
                {
                    printer.WriteLine($"Error {suppression} is not a valid ID.");
                    success = false;
                }
            }
            if (configuration.ExtractPath != null)
            {
                if (!Directory.Exists(configuration.ExtractPath))
                {
                    printer.WriteLine($"Directory {configuration.ExtractPath} does not exist.");
                }
            }
            return success;
        }
    }

}
