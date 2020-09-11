using AuthenticodeExaminer;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace AuthenticodeLinter
{
    class Program
    {
        public static string portalName;
        public static string fileType;
        public static string appName;
        public static int fileNumber;
        public static string fileName;
        public static string filePath;
        public static string validate = "";
        public static Boolean vt = false;
        public static Boolean signed = false;
        public static Boolean InsertRules = true;
        public static Boolean InsertSignature = true;
        public static Boolean InsertSigantureDate = true;
        public static Boolean InsertTSSigantureDate = true;
        public static Boolean InsertTSSiganture = true;
        public static Boolean InsertValidation = true;
        public static Boolean InsertExtension = true;
        public static Boolean InsertApplication = true;
        public static Boolean InsertTSExtension = true;
        public static Boolean InsertPublisher = true;
        public static Boolean InsertRepeatedExtensions = true;
        public static Boolean InsertPublicKeyInfo = true;
        public static Boolean InsertBCRepeatedExtensions = true;
        static async Task Main(string[] args)
        {

            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Console.Error.WriteLine("AuthenticodeLint is only supported on Windows.");
                //return ExitCodes.PlatformNotSupported;
            }
            var cli = Environment.CommandLine;
            List<CommandLineParameter> parsedCommandLine;
            try
            {
                var commandLine = CommandLineParser.LexCommandLine(cli).Skip(1);
                parsedCommandLine = CommandLineParser.CreateCommandLineParametersWithValues(commandLine).ToList();
            }
            catch(InvalidOperationException)
            {
                parsedCommandLine = null;
            }

            if (parsedCommandLine == null || parsedCommandLine.Count == 0 || parsedCommandLine.Any(cl => cl.Name == "help"))
            {
                ShowHelp();
                //Avoid returning success for printing help so that automated build systems do not interpret "show the help"
                //As a successful build incase the build system is incorrectly passing arguments.
                //return ExitCodes.InvalidInputOrConfig;
            }
            var inputs = new List<string>();
            var suppress = new HashSet<int>();
            bool quiet = false;
            bool verbose = false;
            string report = null;
            string extract = null;
            var revocation = RevocationChecking.None;
            var testSet = TestSet.All;
            foreach(var parameter in parsedCommandLine)
            {
                if (parameter.Name == "vt")
                {
                    vt = true;
                }
                else if (parameter.Name == "in")
                {

                    if (string.IsNullOrWhiteSpace(parameter.Value))
                    {
                        Console.Error.WriteLine("A value is required for input.");
                        return;// ExitCodes.InvalidInputOrConfig;
                    }
                    var filePattern = Path.GetFileName(parameter.Value);
                    //The value contains a pattern.
                    if (filePattern.Contains("*") || filePattern.Contains("?"))
                    {
                        var directory = Path.GetDirectoryName(parameter.Value);
                        if (Directory.Exists(directory))
                        {
                            var files = Directory.GetFiles(directory, filePattern, SearchOption.TopDirectoryOnly);
                            inputs.AddRange(files);
                        }
                    }
                    else
                    {
                        inputs.Add(parameter.Value);
                    }
                }
                else if (parameter.Name == "validate")
                {
                    validate = parameter.Value;
                }
                else if(parameter.Name == "portal")
                {
                    portalName = parameter.Value;
                }
                else if (parameter.Name == "app")
                {
                    appName = parameter.Value;
                }
                else if (parameter.Name == "type")
                {
                    fileType = parameter.Value;
                }
                else if (parameter.Name == "number")
                {
                    fileNumber = Int32.Parse(parameter.Value);
                }
                else if (parameter.Name == "suppress")
                {
                    if (string.IsNullOrWhiteSpace(parameter.Value))
                    {
                        ShowInvalidSuppression();
                        return;// ExitCodes.InvalidInputOrConfig;
                    }
                    foreach(var idString in parameter.Value.Split(',').Select(p => p.Trim()))
                    {
                        int id;
                        if (int.TryParse(idString, out id))
                        {
                            suppress.Add(id);
                        }
                        else
                        {
                            Console.Error.WriteLine($"{idString} is not a valid error ID.");
                            return;// ExitCodes.InvalidInputOrConfig;
                        }
                    }
                }
                else if (parameter.Name == "q" || parameter.Name == "quiet")
                {
                    if (!string.IsNullOrWhiteSpace(parameter.Value))
                    {
                        Console.Error.WriteLine($"-{parameter.Name} does not expect a value.");
                        return;// ExitCodes.InvalidInputOrConfig;
                    }
                    quiet = true;
                }
                else if (parameter.Name == "verbose")
                {
                    if (!string.IsNullOrWhiteSpace(parameter.Value))
                    {
                        Console.Error.WriteLine($"-{parameter.Name} does not expect a value.");
                        return;// ExitCodes.InvalidInputOrConfig;
                    }
                    verbose = true;
                }

                else if (parameter.Name == "report")
                {
                    report = parameter.Value;
                }
                else if (parameter.Name == "extract")
                {
                    extract = parameter.Value;
                }
                else if (parameter.Name == "revocation")
                {
                    if (string.IsNullOrWhiteSpace(parameter.Value))
                    {
                        Console.Error.WriteLine($"-{parameter.Name} requires a value if specified.");
                        return;// ExitCodes.InvalidInputOrConfig;
                    }
                    if (!Enum.TryParse(parameter.Value, true, out revocation))
                    {
                        Console.Error.WriteLine($"-{parameter.Value} is an unrecognized revocation mode.");
                        return;// ExitCodes.InvalidInputOrConfig;
                    }
                }
                else if (parameter.Name == "testset")
                {
                    if (string.IsNullOrWhiteSpace(parameter.Value))
                    {
                        Console.Error.WriteLine($"-{parameter.Name} requires a value if specified.");
                        return;// ExitCodes.InvalidInputOrConfig;
                    }
                    if (!Enum.TryParse(parameter.Value, true, out testSet) || parameter.Value.Equals("all", StringComparison.OrdinalIgnoreCase))
                    {
                        Console.Error.WriteLine($"-{parameter.Value} is an unrecognized testset.");
                        return;// ExitCodes.InvalidInputOrConfig;
                    }
                }
                else
                {
                    Console.Error.WriteLine($"-{parameter.Name} is an unknown parameter.");
                    return;// ExitCodes.InvalidInputOrConfig;
                }
            }
            if (inputs.Count == 0)
            {
                Console.Error.WriteLine("Input is expected. See -help for usage.");
                return;// ExitCodes.InvalidInputOrConfig;
            }
            var configuration = new CheckConfiguration(inputs, report, quiet, suppress, verbose, revocation, extract, testSet);

            if (!ConfigurationValidator.ValidateAndPrint(configuration, Console.Error))
            {
                return;// ExitCodes.InvalidInputOrConfig;
            }
            var collectors = new List<ITestResultCollector>();
            if (!quiet)
            {
                collectors.Add(new StdOutTestResultCollector());
            }
            if (!string.IsNullOrWhiteSpace(report))
            {
                collectors.Add(new XmlTestResultCollector(report));
            }
            var result = ExitCodes.Success;
            foreach (var file in inputs)
            {

                    filePath = Path.GetFullPath(file);
                if (!vt && validate.Equals(""))
                {
                    var signatures = SignatureTreeInspector.Extract(file);
                    var verboseWriter = verbose ? new MemorySignatureLogger() : SignatureLogger.Null;
                    fileName = Path.GetFileName(file);
                    if (signatures.Count == 0)
                    {
                        DBConnect.InsertApplicationTable(appName, fileName, portalName, 0, fileType, fileNumber);
                        verboseWriter.LogMessage("File is not Authenticode signed.");

                    }
                    else
                    {
                        DBConnect.InsertApplicationTable(appName, fileName, portalName, 1, fileType, fileNumber);
                        signed = true;
                    }
                    if (CheckEngine.Instance.RunAllTests(file, signatures, collectors, configuration) != TestEngineResult.AllPass)
                    {
                        result = ExitCodes.ChecksFailed;
                    }
                }
                else
                {
                  
                    fileName = Path.GetFileName(file);
                    filePath = Path.GetFullPath(file);
                    if (vt)
                        await VTChecker.GetScanReportForFile();
                  /*  else if (validate.Equals("signature"))
                        Validation.validate(fileName, signatureIndex, thumbprint);*/
                }

            }
            collectors.ForEach(c => c.Flush());
            return;// result;
        }

        static void ShowInvalidSuppression() => Console.Error.WriteLine("Invalid list of errors to suppress. Use -help for more information.");

        static void ShowHelp()
        {
            Console.Out.WriteLine(@"Authenticode Linter

Checks the Authenticode signature of your binaries.

Usage: authlint.exe -in ""C:\path to an\executable.exe""

    -in:            A path to an executable, DLL, or MSI to lint. Can be specified multiple times. Supports wildcards. Required.
    -suppress:      A comma separated list of error IDs to ignore. All checks are run if omitted. Optional.
    -q|quiet:       Run quietly and do not print anything to the output. Optional.
    -report:        A path to produce an XML file as a report. Optional.
    -verbose:       Show verbose output. Cannot be combined with -quiet.
    -revocation:    Specify how revocation checking is done. Valid values are none, offline, online. None is the default.
    -extract:       Extracts all signature information to the specified directory.
    -testset:       A set of tests to run. By intended behavior, such as modern signing, or compatibility.
                    Possible values are ""compat"" and ""modern"", where the default is ""modern"". Optional.

Exit codes:

    0:      All checks passed for all inputs, excluding any that were suppressed.
    1:      Invalid input or configuration was specified.
    2:      One or more checks failed, or the file is not Authenticode signed.
");
        }
    }

    internal static class ExitCodes
    {
        public static int Success => 0;
        public static int InvalidInputOrConfig => 1;
        public static int ChecksFailed => 2;
        public static int UnknownResults => 0xFF;
        public static int PlatformNotSupported => unchecked((int)0x80131539);
    }
}
