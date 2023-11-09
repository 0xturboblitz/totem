pragma circom 2.1.5;

include "./passport.circom";
include "./passport_regex.circom";

template PassportTotem(n, k) {
    signal input mrz[93]; // formatted mrz (5 + 88) chars
    signal input dataHashes[297];
    signal input eContentBytes[104];

    signal input pubkey[k];
    signal input signature[k];
    signal input address;

    // Verify passport
    component PV = PassportVerifier(n, k);
    PV.mrz <== mrz;
    PV.dataHashes <== dataHashes;
    PV.eContentBytes <== eContentBytes;
    PV.pubkey <== pubkey;
    PV.signature <== signature;

    // Reveal name
    signal output name_reveal[83];

    // we shift the mrz by 10 chars to remove :
    // - 5 bytes from the headers
    // - 5 first bytes of the MRZ that indicates the country
    signal mrz_shifted[83];
    for(var i = 0; i < 83; i++) {
        mrz_shifted[i] <== mrz[i+10];
    }

    signal (passport_regex_out, passport_regex_reveal[83]) <== PassportNameRegex(83)(mrz_shifted);
    signal is_found_passport <== IsZero()(passport_regex_out);
    is_found_passport === 0;

    name_reveal <== passport_regex_reveal;
}

component main { public [ address, pubkey, signature ] } = PassportTotem(64, 32);