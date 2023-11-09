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
circom circuits/passport/passport_regex_only.circom -l node_modules --r1cs --sym --wasm --output build

echo "building zkey"
yarn snarkjs groth16 setup build/passport_regex_only.r1cs build/powersOfTau28_hez_final_22.ptau build/passport_regex_only.zkey

echo "building vkey"
echo "test random" | yarn snarkjs zkey contribute build/passport_regex_only.zkey build/passport_regex_only_final.zkey
yarn snarkjs zkey export verificationkey build/passport_regex_only_final.zkey build/passport_regex_only_vk.json
