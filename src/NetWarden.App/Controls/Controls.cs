using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace NetWarden.App.Controls;

/// <summary>Severity donut chart drawn directly (no charting library needed).</summary>
public sealed class DonutChart : FrameworkElement
{
    public static readonly DependencyProperty CriticalProperty = Register(nameof(Critical));
    public static readonly DependencyProperty HighProperty = Register(nameof(High));
    public static readonly DependencyProperty MediumProperty = Register(nameof(Medium));
    public static readonly DependencyProperty LowProperty = Register(nameof(Low));

    private static DependencyProperty Register(string name)
        => DependencyProperty.Register(name, typeof(int), typeof(DonutChart), new FrameworkPropertyMetadata(0, FrameworkPropertyMetadataOptions.AffectsRender));

    public int Critical { get => (int)GetValue(CriticalProperty); set => SetValue(CriticalProperty, value); }
    public int High { get => (int)GetValue(HighProperty); set => SetValue(HighProperty, value); }
    public int Medium { get => (int)GetValue(MediumProperty); set => SetValue(MediumProperty, value); }
    public int Low { get => (int)GetValue(LowProperty); set => SetValue(LowProperty, value); }

    public DonutChart()
    {
        Services.ThemeManager.Changed += InvalidateVisual;
        Unloaded += (_, _) => Services.ThemeManager.Changed -= InvalidateVisual;
        Loaded += (_, _) => { Services.ThemeManager.Changed -= InvalidateVisual; Services.ThemeManager.Changed += InvalidateVisual; };
    }

    private Brush Res(string key, Brush fallback) => TryFindResource(key) as Brush ?? fallback;

    protected override void OnRender(DrawingContext dc)
    {
        var size = Math.Min(ActualWidth, ActualHeight);
        if (size <= 0) return;
        var thickness = size * 0.16;
        var radius = (size - thickness) / 2;
        var center = new Point(ActualWidth / 2, ActualHeight / 2);
        var values = new[]
        {
            (Critical, Res("Brush.Sev.Critical.Solid", Brushes.DarkRed)),
            (High, Res("Brush.Sev.High.Solid", Brushes.OrangeRed)),
            (Medium, Res("Brush.Sev.Medium.Solid", Brushes.Goldenrod)),
            (Low, Res("Brush.Sev.Low.Solid", Brushes.SteelBlue))
        };
        var total = values.Sum(v => v.Item1);
        var track = new Pen(Res("Brush.SegmentBg", Brushes.LightGray), thickness);
        dc.DrawEllipse(null, track, center, radius, radius);
        if (total > 0)
        {
            double start = -90;
            foreach (var (value, brush) in values)
            {
                if (value <= 0) continue;
                var sweep = 360.0 * value / total;
                if (sweep >= 359.99)
                {
                    dc.DrawEllipse(null, new Pen(brush, thickness), center, radius, radius);
                }
                else
                {
                    var geo = Arc(center, radius, start, Math.Max(0.5, sweep - (values.Count(v => v.Item1 > 0) > 1 ? 1.2 : 0)));
                    dc.DrawGeometry(null, new Pen(brush, thickness), geo);
                }
                start += sweep;
            }
        }
        var text = new FormattedText(total.ToString(CultureInfo.CurrentCulture), CultureInfo.CurrentCulture, FlowDirection.LeftToRight,
            new Typeface(new FontFamily("Segoe UI Variable Display, Segoe UI"), FontStyles.Normal, FontWeights.SemiBold, FontStretches.Normal),
            size * 0.2, Res("Brush.Text", Brushes.Black), VisualTreeHelper.GetDpi(this).PixelsPerDip);
        dc.DrawText(text, new Point(center.X - text.Width / 2, center.Y - text.Height / 2));
    }

    private static Geometry Arc(Point c, double r, double startDeg, double sweepDeg)
    {
        double ToRad(double d) => d * Math.PI / 180;
        var p1 = new Point(c.X + r * Math.Cos(ToRad(startDeg)), c.Y + r * Math.Sin(ToRad(startDeg)));
        var p2 = new Point(c.X + r * Math.Cos(ToRad(startDeg + sweepDeg)), c.Y + r * Math.Sin(ToRad(startDeg + sweepDeg)));
        var g = new StreamGeometry();
        using (var ctx = g.Open())
        {
            ctx.BeginFigure(p1, false, false);
            ctx.ArcTo(p2, new Size(r, r), 0, sweepDeg > 180, SweepDirection.Clockwise, true, false);
        }
        g.Freeze();
        return g;
    }
}

public sealed class InverseBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value is bool b ? !b : value;
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => value is bool b ? !b : value;
}

/// <summary>Visible when the value is "something": true, non-null, non-empty string, non-zero number.</summary>
public sealed class HasValueToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; }

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        bool has = value switch
        {
            null => false,
            bool b => b,
            string s => s.Length > 0,
            int i => i != 0,
            long l => l != 0,
            double d => d != 0,
            System.Collections.ICollection c => c.Count > 0,
            _ => true
        };
        if (Invert) has = !has;
        return has ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}

/// <summary>Turns a numbered list of strings into "1. step" lines.</summary>
public sealed class NumberedLinesConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is IEnumerable<string> lines ? string.Join("\n", lines.Select((l, i) => $"{i + 1}. {l}")) : "";

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}
