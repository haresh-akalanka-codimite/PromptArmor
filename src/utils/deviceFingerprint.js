// PromptArmor – Device Fingerprint Generator
// Injected as a content script (needs window / screen / navigator).
// Defines generateFingerprint() in the shared content-script scope so
// content.js can call it directly.

/**
 * Build a SHA-256 fingerprint from stable browser/device properties.
 * Returns { hash: <hex string>, components: <raw values object> }.
 */
async function generateFingerprint() {
  const components = {
    v:        1,                                                    // schema version
    ua:       navigator.userAgent,
    platform: navigator.platform,
    lang:     navigator.language,
    langs:    [...(navigator.languages || [])].slice(0, 3).join(','),
    sw:       screen.width,
    sh:       screen.height,
    cd:       screen.colorDepth,
    dpr:      Math.round((window.devicePixelRatio || 1) * 10) / 10,
    tz:       Intl.DateTimeFormat().resolvedOptions().timeZone,
    cores:    navigator.hardwareConcurrency || 0,
    touch:    navigator.maxTouchPoints     || 0,
    vendor:   navigator.vendor             || ''
  };

  const raw = JSON.stringify(components);
  const buf = await window.crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(raw)
  );
  const hash = Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  return { hash, components };
}
