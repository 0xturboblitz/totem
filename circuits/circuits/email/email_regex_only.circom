pragma circom 2.1.5;

// include "./shorter_email_regex.circom";
// include "./french_gov_email_regex.circom";
include "./short_signed_email_regex.circom";

template RegexWithCheck(n) {
    signal input msg[n];
    signal output name_reveal[n];

    signal (email_regex_out, email_regex_reveal[n]) <== ShortSignedEmailRegex(n)(msg);
    signal is_found_email <== IsZero()(email_regex_out);
    is_found_email === 0;

    name_reveal <== email_regex_reveal;
}

component main = RegexWithCheck(2190);