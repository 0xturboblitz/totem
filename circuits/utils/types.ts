export type DataHash = [number, number[]];

export type PassportData = {
  mrz: string;
  modulus: string;
  dataGroupHashes: DataHash[];
  eContent: number[];
  encryptedDigest: number[];
};
