// Minimal xUnit-compatible shim used only when NuGet is unavailable (NwOffline=true).
// The real build uses the official xunit packages; the test code is identical in both cases.
using System.Reflection;
using System.Text.RegularExpressions;

namespace Xunit
{
    [AttributeUsage(AttributeTargets.Method)]
    public class FactAttribute : Attribute { public string? Skip { get; set; } }

    [AttributeUsage(AttributeTargets.Method)]
    public sealed class TheoryAttribute : FactAttribute { }

    [AttributeUsage(AttributeTargets.Method, AllowMultiple = true)]
    public sealed class InlineDataAttribute : Attribute
    {
        public object?[] Data { get; }
        public InlineDataAttribute(params object?[] data) => Data = data;
    }

    public sealed class XunitException : Exception
    {
        public XunitException(string message) : base(message) { }
    }

    public static class Assert
    {
        public static void True(bool condition, string? message = null) { if (!condition) throw new XunitException(message ?? "Expected true."); }
        public static void False(bool condition, string? message = null) { if (condition) throw new XunitException(message ?? "Expected false."); }
        public static void Null(object? o) { if (o != null) throw new XunitException($"Expected null but was {o}."); }
        public static void NotNull(object? o) { if (o == null) throw new XunitException("Expected not null."); }
        public static void Equal<T>(T expected, T actual)
        {
            if (!EqualityComparer<T>.Default.Equals(expected, actual))
                throw new XunitException($"Expected: {expected}\nActual:   {actual}");
        }
        public static void Equal(double expected, double actual, int precision)
        {
            if (Math.Round(expected, precision) != Math.Round(actual, precision)) throw new XunitException($"Expected {expected} but was {actual}.");
        }
        public static void Equal<T>(T[] expected, T[] actual)
        {
            if (!expected.SequenceEqual(actual)) throw new XunitException($"Arrays differ.\nExpected: {string.Join(",", expected)}\nActual:   {string.Join(",", actual)}");
        }
        public static void Equal<T>(IEnumerable<T> expected, IEnumerable<T> actual)
        {
            if (!expected.SequenceEqual(actual)) throw new XunitException($"Sequences differ.\nExpected: {string.Join(",", expected)}\nActual:   {string.Join(",", actual)}");
        }
        public static void NotEqual<T>(T expected, T actual) { if (EqualityComparer<T>.Default.Equals(expected, actual)) throw new XunitException($"Did not expect {actual}."); }
        public static void Contains(string expected, string? actual) { if (actual == null || !actual.Contains(expected, StringComparison.Ordinal)) throw new XunitException($"'{actual}' does not contain '{expected}'."); }
        public static void DoesNotContain(string expected, string? actual) { if (actual != null && actual.Contains(expected, StringComparison.Ordinal)) throw new XunitException($"'{actual}' contains '{expected}'."); }
        public static void Contains<T>(T expected, IEnumerable<T> collection) { if (!collection.Contains(expected)) throw new XunitException($"Collection does not contain {expected}."); }
        public static void DoesNotContain<T>(T expected, IEnumerable<T> collection) { if (collection.Contains(expected)) throw new XunitException($"Collection contains {expected}."); }
        public static void Contains<T>(IEnumerable<T> collection, Predicate<T> filter) { if (!collection.Any(x => filter(x))) throw new XunitException("No item matched."); }
        public static void DoesNotContain<T>(IEnumerable<T> collection, Predicate<T> filter) { if (collection.Any(x => filter(x))) throw new XunitException("An item matched."); }
        public static void Empty<T>(IEnumerable<T> c) { if (c.Any()) throw new XunitException($"Expected empty but had {c.Count()} item(s)."); }
        public static void NotEmpty<T>(IEnumerable<T> c) { if (!c.Any()) throw new XunitException("Expected not empty."); }
        public static T Single<T>(IEnumerable<T> c)
        {
            var list = c.ToList();
            if (list.Count != 1) throw new XunitException($"Expected exactly one item but had {list.Count}.");
            return list[0];
        }
        public static T Single<T>(IEnumerable<T> c, Predicate<T> filter) => Single(c.Where(x => filter(x)));
        public static void StartsWith(string expected, string? actual) { if (actual == null || !actual.StartsWith(expected, StringComparison.Ordinal)) throw new XunitException($"'{actual}' does not start with '{expected}'."); }
        public static void Matches(string pattern, string? actual) { if (actual == null || !Regex.IsMatch(actual, pattern)) throw new XunitException($"'{actual}' does not match '{pattern}'."); }
        public static void InRange<T>(T actual, T low, T high) where T : IComparable<T>
        {
            if (actual.CompareTo(low) < 0 || actual.CompareTo(high) > 0) throw new XunitException($"{actual} not in [{low}, {high}].");
        }
        public static T Throws<T>(Action action) where T : Exception
        {
            try { action(); }
            catch (T ex) when (ex.GetType() == typeof(T)) { return ex; }
            catch (Exception ex) { throw new XunitException($"Expected {typeof(T).Name} but got {ex.GetType().Name}: {ex.Message}"); }
            throw new XunitException($"Expected {typeof(T).Name} but nothing was thrown.");
        }
        public static async Task<T> ThrowsAsync<T>(Func<Task> action) where T : Exception
        {
            try { await action(); }
            catch (T ex) when (ex.GetType() == typeof(T)) { return ex; }
            catch (Exception ex) { throw new XunitException($"Expected {typeof(T).Name} but got {ex.GetType().Name}: {ex.Message}"); }
            throw new XunitException($"Expected {typeof(T).Name} but nothing was thrown.");
        }
        public static void All<T>(IEnumerable<T> collection, Action<T> action) { foreach (var item in collection) action(item); }
        public static void IsType<T>(object? o) { if (o is not T || o.GetType() != typeof(T)) throw new XunitException($"Expected type {typeof(T).Name} but was {o?.GetType().Name ?? "null"}."); }
    }
}

namespace NetWarden.Tests.OfflineRunner
{
    public static class Program
    {
        public static async Task<int> Main(string[] args)
        {
            int passed = 0, failed = 0;
            var filter = args.FirstOrDefault();
            foreach (var type in typeof(Program).Assembly.GetTypes().Where(t => t.IsClass && t.IsPublic && !t.IsAbstract).OrderBy(t => t.Name))
            {
                foreach (var method in type.GetMethods().Where(m => m.GetCustomAttribute<Xunit.FactAttribute>() != null).OrderBy(m => m.Name))
                {
                    var rows = method.GetCustomAttributes<Xunit.InlineDataAttribute>().Select(a => a.Data).ToList();
                    if (rows.Count == 0) rows.Add(Array.Empty<object?>());
                    foreach (var row in rows)
                    {
                        var name = $"{type.Name}.{method.Name}({string.Join(", ", row.Select(r => r?.ToString() ?? "null"))})";
                        if (filter != null && !name.Contains(filter, StringComparison.OrdinalIgnoreCase)) continue;
                        try
                        {
                            var instance = Activator.CreateInstance(type);
                            var parameters = method.GetParameters();
                            var callArgs = row.Select((v, i) => v == null ? null : Convert.ChangeType(v, Nullable.GetUnderlyingType(parameters[i].ParameterType) ?? parameters[i].ParameterType)).ToArray();
                            var result = method.Invoke(instance, callArgs);
                            if (result is Task t) await t;
                            (instance as IDisposable)?.Dispose();
                            passed++;
                        }
                        catch (Exception ex)
                        {
                            var inner = ex is TargetInvocationException tie ? tie.InnerException ?? ex : ex;
                            failed++;
                            Console.WriteLine($"FAIL {name}\n     {inner.GetType().Name}: {inner.Message.Replace("\n", "\n     ")}");
                        }
                    }
                }
            }
            Console.WriteLine($"\n{passed} passed, {failed} failed");
            return failed == 0 ? 0 : 1;
        }
    }
}
