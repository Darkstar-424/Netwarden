using System.Reflection;
using NetWarden.Core.Checks;
using NetWarden.Core.Models;

namespace NetWarden.Checks;

/// <summary>Convenience base class: sensible defaults so a new check only needs a few overrides.</summary>
public abstract class CheckBase : IVulnerabilityCheck
{
    public abstract string Id { get; }
    public abstract string Name { get; }
    public abstract string Category { get; }
    public virtual CheckScope Scope => CheckScope.Port;
    public virtual ProbeLevel Level => ProbeLevel.VersionOnly;
    public virtual bool RequiresAnonymousLogin => false;
    public virtual bool RequiresNetwork => Level == ProbeLevel.SafeProbe;

    public abstract bool AppliesTo(CheckTarget target);
    public abstract Task<IReadOnlyList<Finding>> RunAsync(CheckContext context, CancellationToken ct);

    protected static Task<IReadOnlyList<Finding>> None() => Task.FromResult<IReadOnlyList<Finding>>(Array.Empty<Finding>());
    protected static Task<IReadOnlyList<Finding>> One(Finding f) => Task.FromResult<IReadOnlyList<Finding>>(new[] { f });
    protected static IReadOnlyList<Finding> List(params Finding[] f) => f;
}

/// <summary>Finds every IVulnerabilityCheck in this assembly (and optional plug-in assemblies).</summary>
public static class CheckRegistry
{
    public static IReadOnlyList<IVulnerabilityCheck> CreateAll(IEnumerable<Assembly>? extraAssemblies = null, string? extraPackFolder = null, Action<string>? warn = null)
    {
        var assemblies = new List<Assembly> { typeof(CheckRegistry).Assembly };
        if (extraAssemblies != null) assemblies.AddRange(extraAssemblies);
        var checks = new List<IVulnerabilityCheck>();
        foreach (var asm in assemblies.Distinct())
        {
            foreach (var type in asm.GetTypes())
            {
                if (type.IsAbstract || type.IsInterface || !typeof(IVulnerabilityCheck).IsAssignableFrom(type)) continue;
                if (type.GetConstructor(Type.EmptyTypes) == null) continue; // template checks are created by the pack loader
                checks.Add((IVulnerabilityCheck)Activator.CreateInstance(type)!);
            }
        }
        checks.AddRange(Packs.CheckPackLoader.LoadAll(extraPackFolder, warn));
        return checks.OrderBy(c => c.Category).ThenBy(c => c.Id).ToList();
    }
}
