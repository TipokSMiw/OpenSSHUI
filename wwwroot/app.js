window.downloadFileFromStream = async (fileName, contentStreamReference) => {
    const arrayBuffer = await contentStreamReference.arrayBuffer();
    const blob = new Blob([arrayBuffer]);
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = fileName ?? '';
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
};

window.copyTextToClipboard = async (text) => {
    if (navigator.clipboard) {
        await navigator.clipboard.writeText(text);
        return true;
    }
    return false;
};

window.getAppLanguage = () => {
    try {
        return localStorage.getItem('opensshui_lang') || 'th';
    } catch {
        return 'th';
    }
};

window.setAppLanguage = (lang) => {
    try {
        localStorage.setItem('opensshui_lang', lang);
    } catch {
        // ignore storage errors
    }
};
