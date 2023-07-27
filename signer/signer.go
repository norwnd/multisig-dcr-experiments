package signer

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/decred/dcrd/txscript/v4"
	"github.com/decred/dcrd/txscript/v4/sign"
	"github.com/decred/dcrd/wire"
	"github.com/norwnd/multisig"
)

// SignRawTransaction returns serialized signed (2 out of 2) txn.
func SignRawTransaction(
	_ context.Context,
	partiallySignedTx string,
	keyDB sign.KeyDB,
	scriptDB sign.ScriptDB,
) (string, error) {
	tx := wire.NewMsgTx()
	err := tx.Deserialize(hex.NewDecoder(strings.NewReader(partiallySignedTx)))
	if err != nil {
		return "", fmt.Errorf("tx.Deserialize: %w", err)
	}
	if len(tx.TxIn) == 0 {
		return "", fmt.Errorf("transaction with no inputs cannot be signed")
	}

	const hashType = txscript.SigHashAll

	// Below we assume working with 2 of 2 multisig, and that each of tx inputs was
	// already signed exactly once, while we need to sign here 2nd time.
	for i, in := range tx.TxIn {
		// TODO - looks like we need to look up prev outpoint and fetch this script from
		// somewhere. Hard-coding for now (fetching from dcrdata manually):
		// https://testnet.dcrdata.org/api/tx/decoded/2c956e08bda061edd9989e4b5af4b3ec6e52a95f88418324aac39c5cf3d672da?indent=true
		// Potentially, we could return prev out script from `redeemMultiSigOut` (or new analogue
		// that supports choosing value we want to transfer) and embed this data in qr code such
		// that Android device doesn't need to look for it anywhere,
		// see this code line (where this fetch happens):
		//   _, outpointScript := p2shOutput.P2SHAddress.PaymentScript()
		//
		// Or we actually can try to construct it ourselves ? since we should have the necessary
		// data (both pub keys) ... is it same as unsigned redeemScript ? not sure ... need to
		// investigate this.
		prevOutUnlockScript, err := hex.DecodeString(multisig.PrevOutUnlockScriptHex)
		if err != nil {
			return "", fmt.Errorf("hex.DecodeString: %w", err)
		}

		//prevOutDisasm, err := txscript.DisasmString(prevOutUnlockScript)
		//if err != nil {
		//	panic(err)
		//}
		//fmt.Println(fmt.Sprintf("PREV_OUT: %s", prevOutDisasm))

		prevScript := in.SignatureScript // 1st signature provided with txn already
		in.SignatureScript = nil         // txn must not contain prev signatures when being signed, both parties must sign same data!
		script, err := sign.SignTxOutput(
			multisig.ChainCfg,
			tx,
			i,
			prevOutUnlockScript, // prev out point unlock script, might be a source of some data (probably unnecessary for our use case)
			hashType,
			keyDB,
			scriptDB,
			prevScript,
			true,
		)
		if err != nil {
			return "", fmt.Errorf("sign.SignTxOutput: %w", err)
		}

		disasmScriptBefore, err := txscript.DisasmString(prevScript)
		if err != nil {
			panic(err)
		}
		fmt.Println(fmt.Sprintf("BEFORE: %s", disasmScriptBefore))

		in.SignatureScript = script // 2 of 2 signature now

		disasmScriptAfter, err := txscript.DisasmString(in.SignatureScript)
		if err != nil {
			panic(err)
		}
		fmt.Println(fmt.Sprintf("AFTER: %s", disasmScriptAfter))

		// TODO - self check
		const (
			// sanityVerifyFlags are the flags used to enable and disable features of
			// the txscript engine used for sanity checking of transactions signed by
			// the wallet.
			sanityVerifyFlags = txscript.ScriptDiscourageUpgradableNops |
				txscript.ScriptVerifyCleanStack |
				txscript.ScriptVerifyCheckLockTimeVerify |
				txscript.ScriptVerifyCheckSequenceVerify |
				txscript.ScriptVerifyTreasury

			// The assumed output script version is defined to assist with refactoring to
			// use actual script versions.
			scriptVersionAssumed = 0
		)

		// Verify txn has been fully signed and is ready for execution in blockchain.
		vm, err := txscript.NewEngine(prevOutUnlockScript, tx, i,
			sanityVerifyFlags, scriptVersionAssumed, nil)
		if err == nil {
			err = vm.Execute()
			//// TODO - debugging
			//fmt.Println()
			//fmt.Println("VM EXECUTION ============================================================")
			//disasm, err := vm.DisasmScript(0)
			//if err != nil {
			//	panic(err)
			//}
			//fmt.Println(fmt.Sprintf("%s", disasm))
			//disasm, err = vm.DisasmScript(1)
			//if err != nil {
			//	panic(err)
			//}
			////fmt.Println(fmt.Sprintf("%s", disasm))
			////disasm, err = vm.DisasmScript(2)
			////if err != nil {
			////	panic(err)
			////}
			//fmt.Println(fmt.Sprintf("%s", disasm))
			//fmt.Println()
			//fmt.Println("VM EXECUTION ============================================================")
			//// TODO - debugging
		}
		if err != nil {
			//var multisigNotEnoughSigs bool
			if errors.Is(err, txscript.ErrInvalidStackOperation) {
				return "", fmt.Errorf("vm.Execute(): txscript.ErrInvalidStackOperation: %w", txscript.ErrInvalidStackOperation)
				//pkScript := additionalPrevScripts[txIn.PreviousOutPoint]
				//class, addr := stdscript.ExtractAddrs(scriptVersionAssumed, pkScript, w.ChainParams())
				//if class == stdscript.STScriptHash && len(addr) > 0 {
				//	redeemScript, _ := source.script(addr[0])
				//	if stdscript.IsMultiSigScriptV0(redeemScript) {
				//		multisigNotEnoughSigs = true
				//	}
				//}
			}
			return "", fmt.Errorf("vm.Execute(): some other error: %w", err)
		}
		fmt.Println("vm.Execute() ended just fine")
	}

	var b strings.Builder
	b.Grow(2 * tx.SerializeSize())
	err = tx.Serialize(hex.NewEncoder(&b))
	if err != nil {
		return "", err
	}

	return b.String(), nil
}

// decodeHexStr decodes the hex encoding of a string, possibly prepending a
// leading '0' character if there is an odd number of bytes in the hex string.
// This is to prevent an error for an invalid hex string when using an odd
// number of bytes when calling hex.Decode.
func decodeHexStr(hexStr string) ([]byte, error) {
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("hex string decode failed: %w", err)
	}
	return decoded, nil
}

func checkScripts(msg string, tx *wire.MsgTx, idx int, sigScript, pkScript []byte) error {
	tx.TxIn[idx].SignatureScript = sigScript
	var scriptFlags txscript.ScriptFlags
	vm, err := txscript.NewEngine(pkScript, tx, idx, scriptFlags, 0, nil)
	if err != nil {
		return fmt.Errorf("failed to make script engine for %s: %v",
			msg, err)
	}

	err = vm.Execute()
	if err != nil {
		return fmt.Errorf("invalid script signature for %s: %v", msg,
			err)
	}

	return nil
}
