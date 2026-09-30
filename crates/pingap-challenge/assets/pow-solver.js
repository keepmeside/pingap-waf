// Proof-of-work solver. Reads every value it needs from the rendered form's
// input attributes — nothing is interpolated into this script — so no
// request-derived string ever reaches code position (the page's injection-XSS
// rule). Runs the SHA-256(salt + decimal(nonce)) search in a yielding loop so
// the interstitial stays responsive, fills the nonce field, and submits.
(() => {
    const form = document.querySelector("form");
    if (!form) return;
    const read = (name) =>
        document.querySelector(`input[name="${name}"]`)?.value;
    const salt = read("challenge_salt");
    const difficulty = parseInt(read("challenge_difficulty") || "0", 10);
    const token = read("challenge_token");
    if (!salt || !token || !(difficulty > 0)) return;

    const status = document.getElementById("pow-status");
    const field = document.querySelector('input[name="nonce"]');
    const button = form.querySelector('button[type="submit"], button');
    if (button) {
        button.disabled = true;
    }

    const enc = new TextEncoder();
    const full = difficulty >> 3;
    const rem = difficulty & 7;
    // The leading `rem` bits of digest[full] must be zero: left-shifting the byte
    // into the low position compares exactly those bits, matching the server's
    // `byte >> (8 - rem) == 0`.
    const mask = rem === 0 ? 0 : 0xff << (8 - rem);

    const meets = (bytes) => {
        for (let i = 0; i < full; i++) {
            if (bytes[i] !== 0) return false;
        }
        return rem === 0 || (bytes[full] & mask) === 0;
    };

    let nonce = 0;
    const BATCH = 2048;
    const start = performance.now();

    const tick = async () => {
        for (let i = 0; i < BATCH; i++, nonce++) {
            const digest = new Uint8Array(
                await crypto.subtle.digest("SHA-256", enc.encode(salt + nonce)),
            );
            if (meets(digest)) {
                if (field) field.value = String(nonce);
                if (status) {
                    const ms = Math.round(performance.now() - start);
                    status.textContent = `Verified in ${ms} ms. Sending…`;
                }
                form.submit();
                return;
            }
        }
        if (status && nonce % (BATCH * 8) === 0) {
            status.textContent = `Working… ${nonce.toLocaleString()} hashes`;
        }
        setTimeout(tick, 0);
    };
    tick();
})();
