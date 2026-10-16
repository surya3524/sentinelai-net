namespace SentinelAI.Tests;

internal static class Paths
{
    private static readonly string AgentDir = FindAgentDir();

    public static string DemoPolicy => Path.Combine(AgentDir, "sentinel.yaml");
    public static string Cases => Path.Combine(AgentDir, "cases");

    // Use the source folder, not bin/, so newly added case files are picked up without a rebuild.
    private static string FindAgentDir()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "demo", "Demo.Agent");
            if (File.Exists(Path.Combine(candidate, "sentinel.yaml"))) return candidate;
        }
        throw new DirectoryNotFoundException("Could not find demo/Demo.Agent above the test output folder.");
    }
}
