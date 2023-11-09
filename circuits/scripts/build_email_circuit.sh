mkdir -p build
cd build    
if [ ! -f powersOfTau28_hez_final_22.ptau ]; then
    echo "Download power of tau...."
    wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_22.ptau
    echo "Finished download!"
else 
    echo "Powers of tau file already downloaded... Skip download action!"
fi
cd ..

echo "compiling circuit"
circom circuits/email/french_gov_email.circom -l node_modules --r1cs --sym --wasm --output build

echo "building zkey"
yarn snarkjs groth16 setup build/french_gov_email.r1cs build/powersOfTau28_hez_final_22.ptau build/french_gov_email.zkey

echo "building vkey"
echo "test random" | yarn snarkjs zkey contribute build/french_gov_email.zkey build/french_gov_email_final.zkey
yarn snarkjs zkey export verificationkey build/french_gov_email_final.zkey build/french_gov_email_vk.json
