// web-trace stealth.js — Anti-detection patches
// Target: Playwright/CDP fingerprint yang terlihat seperti browser biasa

(function() {
    'use strict';

    // ═══════════════════════════════════════════════════════════════
    // 1. Remove ALL automation indicators
    // ═══════════════════════════════════════════════════════════════

    // navigator.webdriver → must be false/undefined
    Object.defineProperty(navigator, 'webdriver', {
        get: () => false,
        configurable: true,
    });

    // Delete cdc_ properties (ChromeDriver leftovers)
    for (let key in document) {
        if (/^cdc_/.test(key)) {
            delete document[key];
        }
    }
    // Also check window
    for (let key in window) {
        if (/^cdc_|^__webdriver|^__driver|^__selenium|^__fxdriver|^__lastWatir/.test(key)) {
            try { delete window[key]; } catch(e) {}
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // 2. Chrome object — must look real
    // ═══════════════════════════════════════════════════════════════

    if (!window.chrome) {
        window.chrome = {};
    }
    if (!window.chrome.runtime) {
        window.chrome.runtime = {
            connect: function() {},
            sendMessage: function() {},
            onMessage: { addListener: function() {}, removeListener: function() {} },
            PlatformOs: { MAC: 'mac', WIN: 'win', ANDROID: 'android', CROS: 'cros', LINUX: 'linux', OPENBSD: 'openbsd' },
            PlatformArch: { ARM: 'arm', X86_32: 'x86-32', X86_64: 'x86-64', MIPS: 'mips', MIPS64: 'mips64' },
            PlatformNaclArch: { ARM: 'arm', X86_32: 'x86-32', X86_64: 'x86-64', MIPS: 'mips', MIPS64: 'mips64' },
            RequestUpdateCheckStatus: { THROTTLED: 'throttled', NO_UPDATE: 'no_update', UPDATE_AVAILABLE: 'update_available' },
            OnInstalledReason: { INSTALL: 'install', UPDATE: 'update', CHROME_UPDATE: 'chrome_update', SHARED_MODULE_UPDATE: 'shared_module_update' },
            OnRestartRequiredReason: { APP_UPDATE: 'app_update', OS_UPDATE: 'os_update', PERIODIC: 'periodic' },
        };
    }
    window.chrome.loadTimes = function() {
        return {
            commitLoadTime: performance.timing.responseStart / 1000,
            connectionInfo: 'http/1.1',
            finishDocumentLoadTime: performance.timing.domContentLoadedEventEnd / 1000,
            finishLoadTime: performance.timing.loadEventEnd / 1000,
            firstPaintAfterLoadTime: 0,
            firstPaintTime: performance.timing.domContentLoadedEventEnd / 1000,
            navigationType: 'Other',
            npnNegotiatedProtocol: 'unknown',
            requestTime: performance.timing.navigationStart / 1000,
            startLoadTime: performance.timing.navigationStart / 1000,
            wasAlternateProtocolAvailable: false,
            wasFetchedViaSpdy: false,
            wasNpnNegotiated: false,
        };
    };
    window.chrome.csi = function() {
        return {
            onloadT: performance.timing.domContentLoadedEventEnd,
            pageT: performance.now(),
            startE: performance.timing.navigationStart,
            tran: 15,
        };
    };

    // ═══════════════════════════════════════════════════════════════
    // 3. Permissions API — realistic responses
    // ═══════════════════════════════════════════════════════════════

    const originalQuery = navigator.permissions.query.bind(navigator.permissions);
    navigator.permissions.query = (parameters) => {
        if (parameters.name === 'notifications') {
            return Promise.resolve({
                state: Notification.permission,
                onchange: null,
                addEventListener: function() {},
                removeEventListener: function() {},
                dispatchEvent: function() { return true; },
            });
        }
        return originalQuery(parameters);
    };

    // ═══════════════════════════════════════════════════════════════
    // 4. Plugins — must have realistic entries
    // ═══════════════════════════════════════════════════════════════

    const fakePlugins = [
        { name: 'Chrome PDF Plugin', description: 'Portable Document Format', filename: 'internal-pdf-viewer', length: 1 },
        { name: 'Chrome PDF Viewer', description: '', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', length: 1 },
        { name: 'Native Client', description: '', filename: 'internal-nacl-plugin', length: 2 },
    ];

    Object.defineProperty(navigator, 'plugins', {
        get: function() {
            const list = fakePlugins.map(p => {
                const plugin = Object.create(Plugin.prototype);
                Object.defineProperties(plugin, {
                    name: { value: p.name },
                    description: { value: p.description },
                    filename: { value: p.filename },
                    length: { value: p.length },
                });
                return plugin;
            });
            list.length = fakePlugins.length;
            list.refresh = function() {};
            list.item = function(i) { return list[i] || null; };
            list.namedItem = function(name) { return list.find(p => p.name === name) || null; };
            return list;
        },
    });

    Object.defineProperty(navigator, 'mimeTypes', {
        get: function() {
            const types = [
                { type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format' },
                { type: 'application/x-google-chrome-pdf', suffixes: 'pdf', description: 'Portable Document Format' },
            ];
            const list = types.map(t => {
                const mime = Object.create(MimeType.prototype);
                Object.defineProperties(mime, {
                    type: { value: t.type },
                    suffixes: { value: t.suffixes },
                    description: { value: t.description },
                });
                return mime;
            });
            list.length = types.length;
            list.item = function(i) { return list[i] || null; };
            list.namedItem = function(name) { return list.find(m => m.type === name) || null; };
            return list;
        },
    });

    // ═══════════════════════════════════════════════════════════════
    // 5. Languages — consistent
    // ═══════════════════════════════════════════════════════════════

    Object.defineProperty(navigator, 'languages', {
        get: () => Object.freeze(['en-US', 'en']),
    });
    Object.defineProperty(navigator, 'language', {
        get: () => 'en-US',
    });

    // ═══════════════════════════════════════════════════════════════
    // 6. Platform — consistent with User-Agent
    // ═══════════════════════════════════════════════════════════════

    Object.defineProperty(navigator, 'platform', {
        get: () => {
            const ua = navigator.userAgent;
            if (ua.includes('Windows')) return 'Win32';
            if (ua.includes('Mac')) return 'MacIntel';
            if (ua.includes('Linux')) return 'Linux x86_64';
            return 'Win32';
        },
    });

    // ═══════════════════════════════════════════════════════════════
    // 7. Hardware concurrency — realistic
    // ═══════════════════════════════════════════════════════════════

    Object.defineProperty(navigator, 'hardwareConcurrency', {
        get: () => 8,
    });

    // ═══════════════════════════════════════════════════════════════
    // 8. Device memory — realistic
    // ═══════════════════════════════════════════════════════════════

    if (navigator.deviceMemory === undefined) {
        Object.defineProperty(navigator, 'deviceMemory', {
            get: () => 8,
        });
    }

    // ═══════════════════════════════════════════════════════════════
    // 9. Connection — realistic NetworkInformation
    // ═══════════════════════════════════════════════════════════════

    if (!navigator.connection) {
        Object.defineProperty(navigator, 'connection', {
            get: () => ({
                downlink: 10,
                effectiveType: '4g',
                rtt: 50,
                saveData: false,
                type: 'wifi',
                onchange: null,
                addEventListener: function() {},
                removeEventListener: function() {},
                dispatchEvent: function() { return true; },
            }),
        });
    }

    // ═══════════════════════════════════════════════════════════════
    // 10. WebGL — spoof vendor/renderer to match Chrome
    // ═══════════════════════════════════════════════════════════════

    const getParameterProxyHandler = {
        apply: function(target, ctx, args) {
            const param = args[0];
            const result = target.apply(ctx, args);
            // UNMASKED_VENDOR_WEBGL = 0x9245
            if (param === 0x9245) {
                return 'Google Inc. (NVIDIA)';
            }
            // UNMASKED_RENDERER_WEBGL = 0x9246
            if (param === 0x9246) {
                return 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 Direct3D11 vs_5_0 ps_5_0, D3D11)';
            }
            return result;
        },
    };

    try {
        const canvas = document.createElement('canvas');
        // Ensure WebGL context exists
        const getContextOrig = HTMLCanvasElement.prototype.getContext;
        HTMLCanvasElement.prototype.getContext = function(type, attrs) {
            if (type === 'webgl' || type === 'experimental-webgl' || type === 'webgl2') {
                attrs = attrs || {};
                if (!attrs.failIfMajorPerformanceCaveat) {
                    attrs.failIfMajorPerformanceCaveat = false;
                }
            }
            return getContextOrig.call(this, type, attrs);
        };

        let gl = canvas.getContext('webgl', { failIfMajorPerformanceCaveat: false })
                 || canvas.getContext('experimental-webgl', { failIfMajorPerformanceCaveat: false });

        // If WebGL is truly unavailable (headless shell without GPU), mock it
        if (!gl) {
            const mockGL = {
                getParameter: function(param) {
                    if (param === 0x1F01) return 'Google Inc. (NVIDIA)'; // RENDERER
                    if (param === 0x1F00) return 'Google Inc. (NVIDIA)'; // VENDOR
                    if (param === 0x9245) return 'Google Inc. (NVIDIA)'; // UNMASKED_VENDOR
                    if (param === 0x9246) return 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 Direct3D11 vs_5_0 ps_5_0, D3D11)';
                    if (param === 0x0D33) return 16384; // MAX_TEXTURE_SIZE
                    if (param === 0x851C) return 16384; // MAX_RENDERBUFFER_SIZE
                    return null;
                },
                getExtension: function(name) {
                    if (name === 'WEBGL_debug_renderer_info') return {};
                    return null;
                },
                getSupportedExtensions: function() {
                    return ['WEBGL_debug_renderer_info', 'OES_texture_float', 'OES_standard_derivatives'];
                },
                canvas: canvas,
            };
            // Patch getContext to return our mock for webgl
            HTMLCanvasElement.prototype.getContext = function(type, attrs) {
                if (type === 'webgl' || type === 'experimental-webgl' || type === 'webgl2') {
                    return mockGL;
                }
                return getContextOrig.call(this, type, attrs);
            };
        } else {
            const originalGetParameter = gl.getParameter.bind(gl);
            gl.getParameter = new Proxy(originalGetParameter, getParameterProxyHandler);
        }
    } catch(e) {}

    // ═══════════════════════════════════════════════════════════════
    // 11. Canvas fingerprint — add subtle noise
    // ═══════════════════════════════════════════════════════════════

    const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
    const originalToBlob = HTMLCanvasElement.prototype.toBlob;
    const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;

    // Deterministic noise based on domain
    function noiseSeed() {
        let hash = 0;
        for (let i = 0; i < location.hostname.length; i++) {
            hash = ((hash << 5) - hash) + location.hostname.charCodeAt(i);
            hash |= 0;
        }
        return Math.abs(hash);
    }

    // Only add noise to toDataURL (most fingerprinters use this)
    HTMLCanvasElement.prototype.toDataURL = function(type, quality) {
        // Add minimal noise to a few pixels
        try {
            const ctx = this.getContext('2d');
            if (ctx && this.width > 0 && this.height > 0) {
                const imgData = ctx.getImageData(0, 0, Math.min(this.width, 4), Math.min(this.height, 4));
                const seed = noiseSeed();
                for (let i = 0; i < imgData.data.length; i += 4) {
                    // Shift one channel by ±1 (imperceptible)
                    imgData.data[i] = Math.max(0, Math.min(255, imgData.data[i] + ((seed + i) % 3 - 1)));
                }
                ctx.putImageData(imgData, 0, 0);
            }
        } catch(e) {}
        return originalToDataURL.call(this, type, quality);
    };

    // ═══════════════════════════════════════════════════════════════
    // 12. AudioContext fingerprint — subtle noise
    // ═══════════════════════════════════════════════════════════════

    try {
        const origCreateOscillator = AudioContext.prototype.createOscillator;
        const origCreateAnalyser = AudioContext.prototype.createAnalyser;
        const origGetFloatFrequencyData = AnalyserNode.prototype.getFloatFrequencyData;
        const origGetByteFrequencyData = AnalyserNode.prototype.getByteFrequencyData;

        AnalyserNode.prototype.getFloatFrequencyData = function(array) {
            origGetFloatFrequencyData.call(this, array);
            const seed = noiseSeed();
            for (let i = 0; i < array.length; i++) {
                array[i] += ((seed + i) % 100) * 0.0000001;
            }
        };
        AnalyserNode.prototype.getByteFrequencyData = function(array) {
            origGetByteFrequencyData.call(this, array);
            const seed = noiseSeed();
            for (let i = 0; i < array.length; i++) {
                array[i] = Math.max(0, Math.min(255, array[i] + ((seed + i) % 3 - 1)));
            }
        };
    } catch(e) {}

    // ═══════════════════════════════════════════════════════════════
    // 13. ClientRects — subtle noise
    // ═══════════════════════════════════════════════════════════════

    const origGetClientRects = Element.prototype.getClientRects;
    const origGetBoundingClientRect = Element.prototype.getBoundingClientRect;

    Element.prototype.getClientRects = function() {
        const rects = origGetClientRects.call(this);
        // Add imperceptible noise
        const seed = noiseSeed();
        const noise = ((seed % 10) - 5) * 0.0001;
        const result = Object.create(DOMRectList.prototype);
        for (let i = 0; i < rects.length; i++) {
            const r = rects[i];
            result[i] = new DOMRect(r.x + noise, r.y + noise, r.width, r.height);
        }
        result.length = rects.length;
        return result;
    };

    Element.prototype.getBoundingClientRect = function() {
        const rect = origGetBoundingClientRect.call(this);
        const seed = noiseSeed();
        const noise = ((seed % 10) - 5) * 0.0001;
        return new DOMRect(rect.x + noise, rect.y + noise, rect.width, rect.height);
    };

    // ═══════════════════════════════════════════════════════════════
    // 14. Screen — realistic values
    // ═══════════════════════════════════════════════════════════════

    Object.defineProperties(screen, {
        width: { get: () => 1920 },
        height: { get: () => 1080 },
        availWidth: { get: () => 1920 },
        availHeight: { get: () => 1040 },
        colorDepth: { get: () => 24 },
        pixelDepth: { get: () => 24 },
    });

    // ═══════════════════════════════════════════════════════════════
    // 15. Timezone — consistent
    // ═══════════════════════════════════════════════════════════════

    const origDateTimeFormat = Intl.DateTimeFormat;
    const origResolvedOptions = Intl.DateTimeFormat.prototype.resolvedOptions;

    Intl.DateTimeFormat = function(...args) {
        return new origDateTimeFormat(...args);
    };
    Intl.DateTimeFormat.prototype = origDateTimeFormat.prototype;
    Intl.DateTimeFormat.prototype.constructor = Intl.DateTimeFormat;
    Object.keys(origDateTimeFormat).forEach(k => {
        Intl.DateTimeFormat[k] = origDateTimeFormat[k];
    });

    // ═══════════════════════════════════════════════════════════════
    // 16. MediaDevices — realistic
    // ═══════════════════════════════════════════════════════════════

    if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
        const origEnumerate = navigator.mediaDevices.enumerateDevices.bind(navigator.mediaDevices);
        navigator.mediaDevices.enumerateDevices = async function() {
            return [
                { deviceId: '', groupId: '', kind: 'audioinput', label: '' },
                { deviceId: '', groupId: '', kind: 'videoinput', label: '' },
                { deviceId: '', groupId: '', kind: 'audiooutput', label: '' },
            ];
        };
    }

    // ═══════════════════════════════════════════════════════════════
    // 17. SpeechSynthesis — must have voices
    // ═══════════════════════════════════════════════════════════════

    if (window.speechSynthesis) {
        const origGetVoices = speechSynthesis.getVoices.bind(speechSynthesis);
        speechSynthesis.getVoices = function() {
            const voices = origGetVoices();
            if (voices.length === 0) {
                return [
                    { name: 'Google US English', lang: 'en-US', localService: false, default: true, voiceURI: 'Google US English' },
                    { name: 'Google UK English Female', lang: 'en-GB', localService: false, default: false, voiceURI: 'Google UK English Female' },
                ];
            }
            return voices;
        };
    }

    // ═══════════════════════════════════════════════════════════════
    // 18. iframe contentWindow consistency
    // ═══════════════════════════════════════════════════════════════

    try {
        const frame = document.createElement('iframe');
        frame.style.display = 'none';
        document.body.appendChild(frame);
        const cWindow = frame.contentWindow;
        if (cWindow) {
            Object.defineProperty(cWindow.navigator, 'webdriver', {
                get: () => false,
            });
        }
        document.body.removeChild(frame);
    } catch(e) {}

    // ═══════════════════════════════════════════════════════════════
    // 19. CDP Runtime.enable detection evasion
    // ═══════════════════════════════════════════════════════════════

    // Some anti-bot checks detect if Runtime.enable was called
    // by checking for __cdp_runtime_enabled on objects
    try {
        delete Object.prototype.__cdp_runtime_enabled;
        delete Function.prototype.__cdp_runtime_enabled;
    } catch(e) {}

    // ═══════════════════════════════════════════════════════════════
    // 20. toString() consistency — functions must not leak native code
    // ═══════════════════════════════════════════════════════════════

    const ensureNative = (obj, prop) => {
        try {
            const desc = Object.getOwnPropertyDescriptor(obj, prop);
            if (desc && desc.get) {
                const origGet = desc.get;
                desc.get = function() {
                    return origGet.call(this);
                };
                desc.get.toString = () => `function get ${prop}() { [native code] }`;
                Object.defineProperty(obj, prop, desc);
            }
        } catch(e) {}
    };

    ensureNative(navigator, 'webdriver');
    ensureNative(navigator, 'plugins');
    ensureNative(navigator, 'languages');
    ensureNative(navigator, 'platform');
    ensureNative(navigator, 'hardwareConcurrency');

    // ═══════════════════════════════════════════════════════════════
    // 21. Image loading — fix broken image naturalWidth/Height
    // ═══════════════════════════════════════════════════════════════

    try {
        // Override naturalWidth/Height for broken images (common headless detection)
        const origNaturalWidthDesc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'naturalWidth');
        const origNaturalHeightDesc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'naturalHeight');

        Object.defineProperty(HTMLImageElement.prototype, 'naturalWidth', {
            get: function() {
                const val = origNaturalWidthDesc.get.call(this);
                // If image loaded but has 0 dimensions, it's a broken image test
                if (val === 0 && this.complete && this.src) {
                    return 1; // Return 1 instead of 0
                }
                return val;
            },
            configurable: true,
        });

        Object.defineProperty(HTMLImageElement.prototype, 'naturalHeight', {
            get: function() {
                const val = origNaturalHeightDesc.get.call(this);
                if (val === 0 && this.complete && this.src) {
                    return 1;
                }
                return val;
            },
            configurable: true,
        });
    } catch(e) {}

    // ═══════════════════════════════════════════════════════════════
    // Done
    // ═══════════════════════════════════════════════════════════════

    console.log('[web-trace] stealth patches active');
})();
