mkdir -p build
cd build    
if [ ! -f powersOfTau28_hez_final_20.ptau ]; then
    echo "Download power of tau...."
    wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_20.ptau
    echo "Finished download!"
else 
    echo "Powers of tau file already downloaded... Skip download action!"
fi
cd ..

echo "compiling circuit"
circom circuits/passport/passportTotem.circom -l node_modules --r1cs --sym --wasm --output build

echo "building zkey"
yarn snarkjs groth16 setup build/passportTotem.r1cs build/powersOfTau28_hez_final_20.ptau build/passportTotem.zkey

echo "building vkey"
echo "test random" | yarn snarkjs zkey contribute build/passportTotem.zkey build/passportTotem_final.zkey
yarn snarkjs zkey export verificationkey build/passportTotem_final.zkey build/passportTotem_vk.json
