using System.Collections.ObjectModel;
using System.Windows.Input;
using NetWarden.Core.Discovery;
using NetWarden.Core.Targeting;
using NetWarden.UI.Mvvm;

namespace NetWarden.UI.ViewModels;

public sealed record SubnetSuggestion(string Cidr, string Interface)
{
    public string Label => $"{Cidr}  ({Interface})";
}

/// <summary>Defines what may be scanned. A scope can't be used until the authorization box is ticked.</summary>
public sealed class ScopeViewModel : ObservableObject
{
    private readonly Workspace _ws;
    private ScanScope? _editing;

    public ScopeViewModel(Workspace ws)
    {
        _ws = ws;
        foreach (var (cidr, nic) in ArpResolver.LocalSubnets()) Suggestions.Add(new SubnetSuggestion(cidr, nic));
        NewCommand = new RelayCommand(New);
        SaveCommand = new RelayCommand(() => Save(), () => CanSave);
        DeleteCommand = new RelayCommand(Delete, () => _editing != null && _ws.Scopes.Any(s => s.Id == _editing.Id));
        UseSuggestionCommand = new RelayCommand(p =>
        {
            if (p is SubnetSuggestion s)
            {
                Targets = s.Cidr;
                if (string.IsNullOrWhiteSpace(Name) || Name == "New scope") Name = "My local network";
            }
        });
        ScanNowCommand = new RelayCommand(() => { if (Save()) _ws.Navigate("scan"); }, () => CanSave);
        if (_ws.SelectedScope != null) Edit(_ws.SelectedScope); else New();
    }

    public Workspace Workspace => _ws;
    public ObservableCollection<SubnetSuggestion> Suggestions { get; } = new();
    public bool HasSuggestions => Suggestions.Count > 0;
    public ICommand NewCommand { get; }
    public RelayCommand SaveCommand { get; }
    public RelayCommand DeleteCommand { get; }
    public ICommand UseSuggestionCommand { get; }
    public RelayCommand ScanNowCommand { get; }

    public ScanScope? SelectedScope
    {
        get => _editing != null && _ws.Scopes.Any(s => s.Id == _editing.Id) ? _ws.Scopes.First(s => s.Id == _editing.Id) : null;
        set { if (value != null) Edit(value); }
    }

    private string _name = "", _targets = "", _exclusions = "", _notes = "";
    private bool _authorized, _publicAck;

    public string Name { get => _name; set { if (Set(ref _name, value)) Validate(); } }
    public string Targets { get => _targets; set { if (Set(ref _targets, value)) Validate(); } }
    public string Exclusions { get => _exclusions; set { if (Set(ref _exclusions, value)) Validate(); } }
    public string Notes { get => _notes; set => Set(ref _notes, value); }
    public bool Authorized { get => _authorized; set { if (Set(ref _authorized, value)) Validate(); } }
    public bool PublicAcknowledged { get => _publicAck; set { if (Set(ref _publicAck, value)) Validate(); } }

    private string _error = "", _summary = "", _publicWarning = "";
    public string ValidationError { get => _error; private set { if (Set(ref _error, value)) Raise(nameof(HasError)); } }
    public bool HasError => ValidationError.Length > 0;
    public string AddressSummary { get => _summary; private set => Set(ref _summary, value); }
    public string PublicWarning { get => _publicWarning; private set { if (Set(ref _publicWarning, value)) Raise(nameof(HasPublicTargets)); } }
    public bool HasPublicTargets => PublicWarning.Length > 0;
    public bool IsNew => SelectedScope == null;
    public string AuthorizationRecord => _editing?.AuthorizedAt is DateTimeOffset at ? $"Authorization confirmed by {_editing.AuthorizedBy} on {at.ToLocalTime():g}." : "";

    public bool CanSave =>
        !string.IsNullOrWhiteSpace(Name) && !string.IsNullOrWhiteSpace(Targets) && !HasError && Authorized && (!HasPublicTargets || PublicAcknowledged);

    public string SaveHint => CanSave ? "" :
        string.IsNullOrWhiteSpace(Targets) ? "Enter at least one address, subnet or name." :
        HasError ? "Fix the targets first." :
        !Authorized ? "Tick the permission box to continue." :
        HasPublicTargets && !PublicAcknowledged ? "Confirm the public-address warning to continue." : "";

    private void Validate()
    {
        if (!TargetParser.TryParseList(Targets, out var specs, out var err))
        {
            ValidationError = err ?? "Invalid targets.";
            AddressSummary = "";
            PublicWarning = "";
        }
        else if (!TargetParser.TryParseList(Exclusions, out _, out var exErr))
        {
            ValidationError = "Exclusions: " + exErr;
        }
        else
        {
            var count = TargetParser.CountAddresses(specs);
            var names = specs.Count(s => s.Kind == TargetKind.HostName);
            if (count > TargetParser.MaxAddresses)
                ValidationError = $"That's {count:N0} addresses; the limit is {TargetParser.MaxAddresses:N0} per scope. Split it into smaller scopes.";
            else ValidationError = "";
            AddressSummary = specs.Count == 0 ? "" : $"{count - names:N0} address(es)" + (names > 0 ? $" and {names} name(s)" : "") + " in scope";
            var pub = specs.Where(AddressClassifier.ContainsPublic).Select(s => s.Original).ToList();
            PublicWarning = pub.Count == 0 ? "" :
                $"{string.Join(", ", pub.Take(3))} {(pub.Count == 1 ? "is a public internet address" : "are public internet addresses")}. " +
                "It probably isn't on your own network. Only continue if you own it or have written permission (for example from your hosting provider).";
        }
        Raise(nameof(CanSave), nameof(SaveHint));
        SaveCommand.NotifyCanExecuteChanged();
        ScanNowCommand.NotifyCanExecuteChanged();
    }

    private void New()
    {
        _editing = null;
        Name = Suggestions.Count > 0 ? "My local network" : "New scope";
        Targets = Suggestions.FirstOrDefault()?.Cidr ?? "";
        Exclusions = "";
        Notes = "";
        Authorized = false;
        PublicAcknowledged = false;
        Raise(nameof(SelectedScope), nameof(IsNew), nameof(AuthorizationRecord));
        DeleteCommand.NotifyCanExecuteChanged();
    }

    private void Edit(ScanScope s)
    {
        _editing = s;
        Name = s.Name;
        Targets = s.Targets;
        Exclusions = s.Exclusions;
        Notes = s.Notes;
        Authorized = s.Authorized;
        PublicAcknowledged = s.PublicAddressesAcknowledged;
        Raise(nameof(SelectedScope), nameof(IsNew), nameof(AuthorizationRecord));
        DeleteCommand.NotifyCanExecuteChanged();
    }

    private bool Save()
    {
        if (!CanSave) return false;
        var services = _ws.Services;
        var scope = _editing ?? new ScanScope();
        var targetsChanged = _editing == null || scope.Targets != Targets || scope.Exclusions != Exclusions;
        var newlyAuthorized = !scope.Authorized || targetsChanged;
        scope.Name = Name.Trim();
        scope.Targets = Targets.Trim();
        scope.Exclusions = Exclusions.Trim();
        scope.Notes = Notes;
        scope.Authorized = Authorized;
        scope.PublicAddressesAcknowledged = PublicAcknowledged && HasPublicTargets;
        if (newlyAuthorized)
        {
            scope.AuthorizedBy = services.CurrentUser;
            scope.AuthorizedAt = DateTimeOffset.Now;
            services.History.Audit("scope-authorized", services.CurrentUser, scope.Name, scope.Targets.Replace("\r", "").Replace('\n', ' '), null,
                $"exclusions: {scope.Exclusions.Replace("\r", "").Replace('\n', ' ')}; public addresses acknowledged: {scope.PublicAddressesAcknowledged}");
        }
        services.History.SaveScope(scope);
        _editing = scope;
        _ws.ReloadScopes();
        _ws.SelectedScope = _ws.Scopes.FirstOrDefault(s => s.Id == scope.Id);
        Raise(nameof(SelectedScope), nameof(IsNew), nameof(AuthorizationRecord));
        DeleteCommand.NotifyCanExecuteChanged();
        return true;
    }

    private void Delete()
    {
        if (_editing == null) return;
        if (!_ws.Platform.Confirm("Delete scope", $"Delete the scope \"{_editing.Name}\"? Scan history is kept.")) return;
        _ws.Services.History.DeleteScope(_editing.Id);
        _ws.Services.History.Audit("scope-deleted", _ws.Services.CurrentUser, _editing.Name);
        _ws.ReloadScopes();
        if (_ws.SelectedScope != null) Edit(_ws.SelectedScope); else New();
    }
}
