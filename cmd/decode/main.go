package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/txscript/v4"
	"github.com/decred/dcrd/txscript/v4/stdaddr"
)

func _main() error {
	//// Create a script to use in the example.  Ordinarily this would come from
	//// some other source.
	//hash160 := stdaddr.Hash160([]byte("example"))
	//script, err := txscript.NewScriptBuilder().AddOp(txscript.OP_DUP).
	//	AddOp(txscript.OP_HASH160).AddData(hash160).
	//	AddOp(txscript.OP_EQUALVERIFY).AddOp(txscript.OP_CHECKSIG).Script()
	//if err != nil {
	//	fmt.Printf("failed to build script: %v\n", err)
	//	return err
	//}
	//
	//// Create a tokenizer to iterate the script and count the number of opcodes.
	//const scriptVersion = 0
	//var numOpcodes int
	//tokenizer := txscript.MakeScriptTokenizer(scriptVersion, script)
	//for tokenizer.Next() {
	//	numOpcodes++
	//}
	//if tokenizer.Err() != nil {
	//	fmt.Printf("script failed to parse: %v\n", err)
	//} else {
	//	fmt.Printf("script contains %d opcode(s)\n", numOpcodes)
	//}

	//redeemScriptSignedBytes, err := hex.DecodeString("483045022100cc602eeb6bf36db91933bccaa77b1927912a04db44a9cd3ac215ccfc5429a9e402203d4c73312640a09524ce8ffba8bc9c2e9c73f1ce2ff0ef39bfc7f2123bf9ded601483045022100a9ca4c38923d17e98fdcaf671873fb72c4ddedbf5f954165e28bab331f10f06602203025e629e054897a988cca994122c115c957abc90ef18eb53008baa363f0efe101475221030e4db4d37cfa43553c645ad20ca79ae79eef966f41243628310e7624d33a41452102dc7aaeb575d3170760f3c719befd52805a0301b200a1e4efb700ebcc379a9af552ae")
	//if err != nil {
	//	return fmt.Errorf("hex.DecodeString: %v", err)
	//}
	//redeemScriptBytes := stdscript.MultiSigRedeemScriptFromScriptSigV0(
	//	redeemScriptSignedBytes,
	//)
	//if err != nil {
	//	return fmt.Errorf("stdaddr.NewAddressPubKeyEcdsaSecp256k1V0Raw: %v", err)
	//}
	//fmt.Println(fmt.Sprintf("redeem script: %x", redeemScriptBytes))

	sigScript, err := hex.DecodeString("483045022100e619b9ecc2fd2ec4e3f38be09688c722661e8a1ef3dce09196a7f5dd30eaa25102202fa58fc4344f844ba3194a519c956f0c1baf8b82353d4b3cb9a8e5ba344e0b3901210380dcc0f97c89b186aab2329bae4b30ee920e17a3b6435e4c121178d908cdb4de20e365285e21fc311069cf206d9e56c8eaab996ae84d4c18787640cdb7a6c91253514c616382012088c020a017a12d2dc3f88f98c3225e226e16a5a1d3190a725ab90c32e5b6115620b7d48876a9148a00aafbd40a6e7b619a7b2ca0a8763b4b57507f6704520cbb64b17576a914ce45bc063873330be210f80ebd21acfd9aaf66226888ac")
	if err != nil {
		return fmt.Errorf("hex.DecodeString: %v", err)
	}
	contractHash, err := hex.DecodeString("b5c5936018751a6f427dfc524de0c8f547d183f4")
	if err != nil {
		return fmt.Errorf("hex.DecodeString: %v", err)
	}
	secret, err := FindKeyPush(0, sigScript, contractHash, chaincfg.TestNet3Params())
	if err != nil {
		return fmt.Errorf("hex.DecodeString: %v", err)
	}
	fmt.Println(fmt.Sprintf("secret hash: %x", sha256.Sum256(secret)))
	fmt.Println(fmt.Sprintf("secret: %x", secret))

	//addrBytes, err := hex.DecodeString("abb90acd25884d6238b26a585caf123a7212a5e5")
	//if err != nil {
	//	return fmt.Errorf("hex.DecodeString: %v", err)
	//}
	//addr, err := stdaddr.NewAddressScriptHashFromHash(
	//	0,
	//	addrBytes,
	//	multisig.ChainCfg,
	//)
	//if err != nil {
	//	return fmt.Errorf("stdaddr.NewAddressPubKeyEcdsaSecp256k1V0Raw: %v", err)
	//}
	//fmt.Println(fmt.Sprintf("addr: %s", addr.String()))

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

// SwapContractSize is the worst case scenario size for a swap contract,
// which is the pk-script of the non-change output of an initialization
// transaction as used in execution of an atomic swap.
// See ExtractSwapDetails for a breakdown of the bytes.
const SwapContractSize = 97

// SecretKeySize is the byte-length of the secret key used in an atomic swap.
const SecretKeySize = 32

// FindKeyPush attempts to extract the secret key from the signature script. The
// contract must be provided for the search algorithm to verify the correct data
// push. Only contracts of length SwapContractSize that can be validated by
// ExtractSwapDetails are recognized.
func FindKeyPush(scriptVersion uint16, sigScript, contractHash []byte, chainParams *chaincfg.Params) ([]byte, error) {
	tokenizer := txscript.MakeScriptTokenizer(scriptVersion, sigScript)

	// The contract is pushed after the key, find the contract starting with the
	// first data push and record all data pushes encountered before the contract
	// push. One of those preceding pushes should be the key push.
	var dataPushesUpTillContract [][]byte
	var keyHash []byte
	var err error
	for tokenizer.Next() {
		push := tokenizer.Data()

		// Only hash if ExtractSwapDetails will recognize it.
		if len(push) == SwapContractSize {
			h := dcrutil.Hash160(push)
			if bytes.Equal(h, contractHash) {
				_, _, _, keyHash, err = ExtractSwapDetails(push, chainParams)
				if err != nil {
					return nil, fmt.Errorf("error extracting atomic swap details: %w", err)
				}
				break // contract is pushed after the key, if we've encountered the contract, we must have just passed the key
			}
		}

		// Save this push as preceding the contract push.
		if push != nil {
			dataPushesUpTillContract = append(dataPushesUpTillContract, push)
		}
	}
	if tokenizer.Err() != nil {
		return nil, tokenizer.Err()
	}

	if len(keyHash) > 0 {
		// The key push should be the data push immediately preceding the contract
		// push, but iterate through all of the preceding pushes backwards to ensure
		// it is not hidden behind some non-standard script.
		for i := len(dataPushesUpTillContract) - 1; i >= 0; i-- {
			push := dataPushesUpTillContract[i]

			// We have the key hash from the contract. See if this is the key.
			h := sha256.Sum256(push)
			if bytes.Equal(h[:], keyHash) {
				return push, nil
			}
		}
	}

	return nil, fmt.Errorf("key not found")
}

// ExtractSwapDetails extacts the sender and receiver addresses from a swap
// contract. If the provided script is not a swap contract, an error will be
// returned.
func ExtractSwapDetails(pkScript []byte, chainParams *chaincfg.Params) (
	sender, receiver stdaddr.Address, lockTime uint64, secretHash []byte, err error) {
	// A swap redemption sigScript is <pubkey> <secret> and satisfies the
	// following swap contract, allowing only for a secret of size
	//
	// OP_IF
	//  OP_SIZE OP_DATA_1 secretSize OP_EQUALVERIFY OP_SHA256 OP_DATA_32 secretHash OP_EQUALVERIFY OP_DUP OP_HASH160 OP_DATA20 pkHashReceiver
	//     1   +   1     +    1     +      1       +    1    +    1     +    32    +      1       +   1  +    1     +    1    +    20
	// OP_ELSE
	//  OP_DATA4 lockTime OP_CHECKLOCKTIMEVERIFY OP_DROP OP_DUP OP_HASH160 OP_DATA_20 pkHashSender
	//     1    +    4   +           1          +   1   +  1   +    1     +   1      +    20
	// OP_ENDIF
	// OP_EQUALVERIFY
	// OP_CHECKSIG
	//
	// 5 bytes if-else-endif-equalverify-checksig
	// 1 + 1 + 1 + 1 + 1 + 1 + 32 + 1 + 1 + 1 + 1 + 20 = 62 bytes for redeem block
	// 1 + 4 + 1 + 1 + 1 + 1 + 1 + 20 = 30 bytes for refund block
	// 5 + 62 + 30 = 97 bytes
	//
	// Note that this allows for a secret size of up to 75 bytes, but the secret
	// must be 32 bytes to be considered valid.
	if len(pkScript) != SwapContractSize {
		err = fmt.Errorf("incorrect swap contract length. expected %d, got %d",
			SwapContractSize, len(pkScript))
		return
	}

	if pkScript[0] == txscript.OP_IF &&
		pkScript[1] == txscript.OP_SIZE &&
		pkScript[2] == txscript.OP_DATA_1 &&
		// secretSize (1 bytes)
		pkScript[4] == txscript.OP_EQUALVERIFY &&
		pkScript[5] == txscript.OP_SHA256 &&
		pkScript[6] == txscript.OP_DATA_32 &&
		// secretHash (32 bytes)
		pkScript[39] == txscript.OP_EQUALVERIFY &&
		pkScript[40] == txscript.OP_DUP &&
		pkScript[41] == txscript.OP_HASH160 &&
		pkScript[42] == txscript.OP_DATA_20 &&
		// receiver's pkh (20 bytes)
		pkScript[63] == txscript.OP_ELSE &&
		pkScript[64] == txscript.OP_DATA_4 &&
		// lockTime (4 bytes)
		pkScript[69] == txscript.OP_CHECKLOCKTIMEVERIFY &&
		pkScript[70] == txscript.OP_DROP &&
		pkScript[71] == txscript.OP_DUP &&
		pkScript[72] == txscript.OP_HASH160 &&
		pkScript[73] == txscript.OP_DATA_20 &&
		// sender's pkh (20 bytes)
		pkScript[94] == txscript.OP_ENDIF &&
		pkScript[95] == txscript.OP_EQUALVERIFY &&
		pkScript[96] == txscript.OP_CHECKSIG {

		if ssz := pkScript[3]; ssz != SecretKeySize {
			return nil, nil, 0, nil, fmt.Errorf("invalid secret size %d", ssz)
		}

		receiver, err = stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(pkScript[43:63], chainParams)
		if err != nil {
			return nil, nil, 0, nil, fmt.Errorf("error decoding address from recipient's pubkey hash")
		}

		sender, err = stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(pkScript[74:94], chainParams)
		if err != nil {
			return nil, nil, 0, nil, fmt.Errorf("error decoding address from sender's pubkey hash")
		}

		lockTime = uint64(binary.LittleEndian.Uint32(pkScript[65:69]))
		secretHash = pkScript[7:39]

		return
	}

	err = fmt.Errorf("invalid swap contract")
	return
}
