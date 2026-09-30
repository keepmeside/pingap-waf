const HTML: &str = include_str!("../assets/challenge.html");
const SILENT: &str = include_str!("../assets/silent.js");
const POW_SOLVER: &str = include_str!("../assets/pow-solver.js");

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn pow(
    token: &str,
    salt: &str,
    difficulty: u8,
    action: &str,
    target: &str,
) -> String {
    // The solver script is a fixed asset, appended after the same escaped
    // substitution the silent path uses. It reads token/salt/difficulty back
    // out of the rendered input values, so nothing request-derived is ever
    // written into code position.
    format!(
        "{}<script>{}</script>",
        HTML.replace("{{TOKEN}}", &escape(token))
            .replace("{{SALT}}", &escape(salt))
            .replace("{{DIFFICULTY}}", &difficulty.to_string())
            .replace("{{TARGET}}", &escape(action))
            .replace("{{RETURN}}", &escape(target)),
        POW_SOLVER
    )
}

pub fn silent(token: &str, action: &str, target: &str) -> String {
    format!(
        "{}<script>{}</script>",
        HTML.replace("{{TOKEN}}", &escape(token))
            .replace("{{SALT}}", "")
            .replace("{{DIFFICULTY}}", "0")
            .replace("{{TARGET}}", &escape(action))
            .replace("{{RETURN}}", &escape(target)),
        SILENT
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // A hostile return target that would break out of the page if it ever
    // reached code position unescaped.
    const HOSTILE: &str = "/\u{22}</script><script>alert(1)</script>";

    /// The portion of the rendered page inside the injected `<script>` block.
    fn script_body(rendered: &str) -> &str {
        let start = rendered.find("<script>").map(|i| i + "<script>".len());
        let end = rendered.rfind("</script>");
        match (start, end) {
            (Some(s), Some(e)) if s < e => &rendered[s..e],
            _ => "",
        }
    }

    #[test]
    fn the_pow_page_carries_a_solver_that_reads_inputs_from_the_dom() {
        let page = pow("tok", "salt", 4, "/verify", "/account");
        // A solver script is injected: the interstitial is not a manual form.
        let script = script_body(&page);
        assert!(script.contains("crypto.subtle.digest"));
        assert!(script.contains("challenge_salt"));
        assert!(script.contains("challenge_difficulty"));
        // The script reads values back out of the form rather than being
        // templated — it is identical regardless of the request.
        assert_eq!(script.trim(), POW_SOLVER.trim());
    }

    #[test]
    fn no_request_derived_value_reaches_the_inline_script() {
        for bad in [
            HOSTILE,
            "/\u{27}\u{3c}/script\u{3e}",
            "salt\u{22}\u{3c}/script\u{3e}",
            "token;alert(1)//",
        ] {
            for page in [
                pow("tok", bad, 4, "/verify", bad),
                pow(bad, "salt", 4, "/verify", bad),
                pow("tok", "salt", 4, "/verify", bad),
            ] {
                let script = script_body(&page);
                assert!(
                    !script.contains(bad),
                    "request-derived value reached inline script: {bad:?}"
                );
            }
        }
    }

    #[test]
    fn the_page_renders_the_status_element_the_solver_writes() {
        let page = pow("tok", "salt", 4, "/verify", "/account");
        assert!(page.contains("pow-status"));
        // The nonce field is what the solver fills and the form submits.
        assert!(page.contains("name=\"nonce\""));
    }
}
