pragma circom 2.1.5;

include "../../node_modules/@zk-email/zk-regex-circom/circuits/common/from_addr_regex.circom";
include "../../node_modules/@zk-email/circuits/email-verifier.circom";
include "./short_signed_email_regex.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";

// Here, n and k are the biginteger parameters for RSA
// This is because the number is chunked into k pack_size of n bits each
// Max header bytes shouldn't need to be changed much per email,
// but the max mody bytes may need to be changed to be larger if the email has a lot of i.e. HTML formatting
template GovEmailVerifier(max_header_bytes, max_body_bytes, max_regex_search, n, k, pack_size, expose_from, expose_to, max_name_length) {
    assert(expose_from < 2); // 1 if we should expose the from, 0 if we should not
    assert(expose_to == 0); // 1 if we should expose the to, 0 if we should not: due to hotmail restrictions, we force-disable this

    signal input in_padded[max_header_bytes]; // prehashed email data, includes up to 512 + 64? bytes of padding pre SHA256, and padded with lots of 0s at end after the length
    signal input pubkey[k]; // rsa pubkey, verified with smart contract + DNSSEC proof. split up into k parts of n bits each.
    signal input signature[k]; // rsa signature. split up into k parts of n bits each.
    signal input in_len_padded_bytes; // length of in email data including the padding, which will inform the sha256 block length

    // Identity commitment variables
    // (note we don't need to constrain the + 1 due to https://geometry.xyz/notebook/groth16-malleability)
    signal input address;
    signal input body_hash_idx;
    signal input precomputed_sha[32];
    signal input in_body_padded[max_body_bytes];
    signal input in_body_len_padded_bytes;

    signal input salt;

    component EV = EmailVerifier(max_header_bytes, max_body_bytes, n, k, 0);
    EV.in_padded <== in_padded;
    EV.pubkey <== pubkey;
    EV.signature <== signature;
    EV.in_len_padded_bytes <== in_len_padded_bytes;
    EV.body_hash_idx <== body_hash_idx;
    EV.precomputed_sha <== precomputed_sha;
    EV.in_body_padded <== in_body_padded;
    EV.in_body_len_padded_bytes <== in_body_len_padded_bytes;

    // FROM HEADER REGEX: 736,553 constraints
    // This extracts the from email, and the precise regex format can be viewed in the README
    if(expose_from){
        var max_email_from_len = 30;
        var max_email_from_packed_bytes = count_packed(max_email_from_len, pack_size);
        assert(max_email_from_packed_bytes < max_header_bytes);

        signal input email_from_idx;
        signal output reveal_email_from_packed[max_email_from_packed_bytes]; // packed into 7-bytes. TODO: make this rotate to take up even less space

        signal (from_regex_out, from_regex_reveal[max_header_bytes]) <== FromAddrRegex(max_header_bytes)(in_padded);
        log(from_regex_out);
        from_regex_out === 1;
        reveal_email_from_packed <== ShiftAndPackMaskedStr(max_header_bytes, max_email_from_len, pack_size)(from_regex_reveal, email_from_idx);
    }

    signal regex_input[max_regex_search];
    for(var i = 0; i < max_regex_search; i++){
        regex_input[i] <== in_body_padded[i];
    }

    // Body reveal vars
    var max_name_len = 21;
    signal input name_idx;

    // NAME REGEX: 328,044 constraints
    signal (name_regex_out, name_regex_reveal[max_regex_search]) <== ShortSignedEmailRegex(max_regex_search)(regex_input);
    // This ensures we found a match at least once (i.e. match count is not zero)
    signal is_found_name <== IsZero()(name_regex_out);
    is_found_name === 0;

    component shifter = ShiftAndPackMaskedStr(max_regex_search, max_name_length, 31);
    shifter.in <== name_regex_reveal;
    shifter.shift <== name_idx;

    var packed_name_length = 1;
    signal poseidon_input[packed_name_length + 1];
    for(var i = 0; i < packed_name_length; i++) {
        poseidon_input[i] <== shifter.out[i];
    }
    poseidon_input[packed_name_length] <== salt;

    // Reveal the Poseidon hash of the name (packed_name_length field elements) and the salt (1 field element)
    signal output commitment <== Poseidon(packed_name_length + 1)(poseidon_input);
}


// Args:
// * max_header_bytes = 1024 is the max number of bytes in the header
// * max_body_bytes = 2176 is the max number of bytes in the body after precomputed slice
// * max_regex_search = 300 is the number of bytes the regex looks for the pattern.
// * n = 121 is the number of bits in each chunk of the pubkey (RSA parameter)
// * k = 17 is the number of chunks in the pubkey (RSA parameter). Note 121 * 17 > 2048.
// * pack_size = 31 is the number of bytes that can fit into a 255ish bit signal (can increase later)
// * expose_from = 0 is whether to expose the from email address
// * expose_to = 0 is whether to expose the to email (not recommended)
// * max_name_length = 31 is the maximum length of the name
component main { public [ address, pubkey ] } = GovEmailVerifier(1024, 2176, 300, 121, 17, 31, 0, 0, 31);
