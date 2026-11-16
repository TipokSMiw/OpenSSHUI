namespace OpensshUI.Services.Localization;

/// <summary>
/// Provides per-circuit Thai/English (th/en) localization for Blazor Server components.
/// </summary>
public interface ILocalizationService
{
    /// <summary>
    /// Current active language code ("th" or "en").
    /// </summary>
    string CurrentLanguage { get; }

    /// <summary>
    /// True when the active language is Thai ("th").
    /// </summary>
    bool IsThai { get; }

    /// <summary>
    /// Raised whenever <see cref="CurrentLanguage"/> changes.
    /// </summary>
    event Action? OnLanguageChanged;

    /// <summary>
    /// Resolves the localized string for <paramref name="key"/> in the active language.
    /// Falls back to the key name if not found.
    /// </summary>
    string this[string key] { get; }

    /// <summary>
    /// Resolves and formats a parameterized localized string using <see cref="string.Format(string, object?[])"/>.
    /// </summary>
    string Get(string key, params object[] args);

    /// <summary>
    /// Sets the active language ("th" or "en"; any unsupported value falls back to "th")
    /// and raises <see cref="OnLanguageChanged"/> if changed.
    /// </summary>
    void SetLanguage(string languageCode);

    /// <summary>
    /// Loads persisted language preference from browser localStorage via named JS interop.
    /// </summary>
    Task InitializeAsync();

    /// <summary>
    /// Sets the active language and persists it to browser localStorage via named JS interop.
    /// </summary>
    Task SetLanguageAndPersistAsync(string languageCode);
}
