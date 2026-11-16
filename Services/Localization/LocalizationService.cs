using Microsoft.JSInterop;

namespace OpensshUI.Services.Localization;

/// <summary>
/// Scoped per-circuit localization service backed by static immutable <see cref="AppStrings"/> dictionaries
/// and browser localStorage persistence via named JS functions (zero eval).
/// </summary>
public sealed class LocalizationService : ILocalizationService
{
    private readonly IJSRuntime? _jsRuntime;
    private bool _initialized;

    public LocalizationService(IJSRuntime? jsRuntime = null)
    {
        _jsRuntime = jsRuntime;
    }

    public string CurrentLanguage { get; private set; } = AppStrings.DefaultLanguage;

    public bool IsThai => string.Equals(CurrentLanguage, AppStrings.Thai, StringComparison.Ordinal);

    public event Action? OnLanguageChanged;

    public string this[string key] => AppStrings.Get(key, CurrentLanguage);

    public string Get(string key, params object[] args)
    {
        var template = AppStrings.Get(key, CurrentLanguage);
        if (args.Length == 0)
        {
            return template;
        }

        try
        {
            return string.Format(template, args);
        }
        catch (FormatException)
        {
            return template;
        }
    }

    public void SetLanguage(string languageCode)
    {
        var normalized = AppStrings.NormalizeLanguage(languageCode);
        if (string.Equals(CurrentLanguage, normalized, StringComparison.Ordinal))
        {
            return;
        }

        CurrentLanguage = normalized;
        OnLanguageChanged?.Invoke();
    }

    public async Task InitializeAsync()
    {
        if (_initialized || _jsRuntime == null)
        {
            return;
        }

        _initialized = true;
        try
        {
            var stored = await _jsRuntime.InvokeAsync<string?>("getAppLanguage");
            if (!string.IsNullOrWhiteSpace(stored))
            {
                SetLanguage(stored);
            }
        }
        catch (InvalidOperationException)
        {
            // Prerendering: JS interop not yet available
            _initialized = false;
        }
        catch (JSDisconnectedException)
        {
            // Circuit disconnected
        }
        catch (JSException)
        {
            // Ignore storage errors
        }
    }

    public async Task SetLanguageAndPersistAsync(string languageCode)
    {
        var normalized = AppStrings.NormalizeLanguage(languageCode);
        SetLanguage(normalized);

        if (_jsRuntime == null)
        {
            return;
        }

        try
        {
            await _jsRuntime.InvokeVoidAsync("setAppLanguage", normalized);
        }
        catch (InvalidOperationException)
        {
            // Prerendering
        }
        catch (JSDisconnectedException)
        {
            // Circuit disconnected
        }
        catch (JSException)
        {
            // Ignore storage errors
        }
    }
}
