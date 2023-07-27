package main

import (
	"encoding/hex"
	"fmt"
	"github.com/decred/dcrd/txscript/v4/stdscript"
	"os"
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

	redeemScriptSignedBytes, err := hex.DecodeString("483045022100cc602eeb6bf36db91933bccaa77b1927912a04db44a9cd3ac215ccfc5429a9e402203d4c73312640a09524ce8ffba8bc9c2e9c73f1ce2ff0ef39bfc7f2123bf9ded601483045022100a9ca4c38923d17e98fdcaf671873fb72c4ddedbf5f954165e28bab331f10f06602203025e629e054897a988cca994122c115c957abc90ef18eb53008baa363f0efe101475221030e4db4d37cfa43553c645ad20ca79ae79eef966f41243628310e7624d33a41452102dc7aaeb575d3170760f3c719befd52805a0301b200a1e4efb700ebcc379a9af552ae")
	if err != nil {
		return fmt.Errorf("hex.DecodeString: %v", err)
	}
	redeemScriptBytes := stdscript.MultiSigRedeemScriptFromScriptSigV0(
		redeemScriptSignedBytes,
	)
	if err != nil {
		return fmt.Errorf("stdaddr.NewAddressPubKeyEcdsaSecp256k1V0Raw: %v", err)
	}
	fmt.Println(fmt.Sprintf("redeem script: %x", redeemScriptBytes))

	stdscript.ExtractAtomicSwapDataPushesV0()

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
