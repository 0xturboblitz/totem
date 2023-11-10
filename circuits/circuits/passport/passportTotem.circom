pragma circom 2.1.5;

include "./passport.circom";
include "./passport_regex.circom";

template PassportTotem(max_name_length, n, k) {
    signal input mrz[93]; // formatted mrz (5 + 88) chars
    signal input dataHashes[297];
    signal input eContentBytes[104];

    signal input pubkey[k];
    signal input signature[k];
    signal input address;

    signal input salt;

    // Verify passport
    component PV = PassportVerifier(n, k);
    PV.mrz <== mrz;
    PV.dataHashes <== dataHashes;
    PV.eContentBytes <== eContentBytes;
    PV.pubkey <== pubkey;
    PV.signature <== signature;

    // we shift the mrz by 10 chars to remove :
    // - 5 bytes from the headers
    // - 5 first bytes of the MRZ that indicates the country
    signal mrz_shifted[max_name_length];
    for(var i = 0; i < max_name_length; i++) {
        mrz_shifted[i] <== mrz[i+10];
    }

    signal (passport_regex_out, passport_regex_reveal[max_name_length]) <== PassportNameRegex(max_name_length)(mrz_shifted);
    signal is_found_passport <== IsZero()(passport_regex_out);
    is_found_passport === 0;

    // pack the name padded with 0s (max_name_length bytes) into chunk_number field elements,
    var packed_name_length = 1; // ceil(n/31)
    signal name_packed[packed_name_length] <== PackBytes(max_name_length, packed_name_length, 31)(passport_regex_reveal);

    signal poseidon_input[packed_name_length + 1];
    for(var i = 0; i < packed_name_length; i++) {
        poseidon_input[i] <== name_packed[i];
    }
    poseidon_input[packed_name_length] <== salt;

    // Reveal the Poseidon hash of the name (packed_name_length field elements) and the salt (1 field element)
    signal output commitment <== Poseidon(packed_name_length + 1)(poseidon_input);
}

component main { public [ address, pubkey, signature ] } = PassportTotem(31, 64, 32);