// Copyright (c) 2014-2016 The btcsuite developers
// Copyright (c) 2015-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package multisig_test

import (
	"errors"
	"fmt"
	mrand "math/rand"
	"testing"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrec"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/txscript/v4"
	"github.com/decred/dcrd/txscript/v4/sign"
	"github.com/decred/dcrd/txscript/v4/stdaddr"
	"github.com/decred/dcrd/txscript/v4/stdscript"
	"github.com/decred/dcrd/wire"
)

//
//const (
//	// noTreasury signifies the treasury agenda should be treated as though
//	// it is inactive.  It is used to increase the readability of the
//	// tests.
//	noTreasury = false
//)
//
//// This example demonstrates manually creating and signing a redeem transaction.
//func Examplesign.SignTxOutput() {
//	// Ordinarily the private key would come from whatever storage mechanism
//	// is being used, but for this example just hard code it.
//	privKeyBytes, err := hex.DecodeString("22a47fa09a223f2aa079edf85a7c2" +
//		"d4f8720ee63e502ee2869afab7de234b80c")
//	if err != nil {
//		fmt.Println(err)
//		return
//	}
//	pubKey := secp256k1.PrivKeyFromBytes(privKeyBytes).PubKey()
//	pubKeyHash := stdaddr.Hash160(pubKey.SerializeCompressed())
//	mainNetParams := chaincfg.MainNetParams()
//	addr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(pubKeyHash,
//		mainNetParams)
//	if err != nil {
//		fmt.Println(err)
//		return
//	}
//
//	fmt.Println(fmt.Sprintf("pubKey: %x", pubKey.SerializeCompressed()))
//	fmt.Println(fmt.Sprintf("pubKeyHash: %x", pubKeyHash))
//
//	// For this example, create a fake transaction that represents what
//	// would ordinarily be the real transaction that is being spent.  It
//	// contains a single output that pays to address in the amount of 1 DCR.
//	originTx := wire.NewMsgTx()
//	prevOut := wire.NewOutPoint(&chainhash.Hash{}, ^uint32(0), wire.TxTreeRegular)
//	txIn := wire.NewTxIn(prevOut, 100000000, []byte{txscript.OP_0, txscript.OP_0})
//	originTx.AddTxIn(txIn)
//	pkScriptVer, pkScript := addr.PaymentScript()
//	txOut := wire.NewTxOut(100000000, pkScript)
//	txOut.Version = pkScriptVer
//	originTx.AddTxOut(txOut)
//	originTxHash := originTx.TxHash()
//
//	// Create the transaction to redeem the fake transaction.
//	redeemTx := wire.NewMsgTx()
//
//	// Add the input(s) the redeeming transaction will spend.  There is no
//	// signature script at this point since it hasn't been created or signed
//	// yet, hence nil is provided for it.
//	prevOut = wire.NewOutPoint(&originTxHash, 0, wire.TxTreeRegular)
//	txIn = wire.NewTxIn(prevOut, 100000000, nil)
//	redeemTx.AddTxIn(txIn)
//
//	// Ordinarily this would contain that actual destination of the funds,
//	// but for this example don't bother.
//	txOut = wire.NewTxOut(0, nil)
//	redeemTx.AddTxOut(txOut)
//
//	// Sign the redeeming transaction.
//	sigType := dcrec.STEcdsaSecp256k1
//	lookupKey := func(a stdaddr.Address) ([]byte, dcrec.SignatureType, bool, error) {
//		// Ordinarily this function would involve looking up the private
//		// key for the provided address, but since the only thing being
//		// signed in this example uses the address associated with the
//		// private key from above, simply return it with the compressed
//		// flag set since the address is using the associated compressed
//		// public key.
//		//
//		// NOTE: If you want to prove the code is actually signing the
//		// transaction properly, uncomment the following line which
//		// intentionally returns an invalid key to sign with, which in
//		// turn will result in a failure during the script execution
//		// when verifying the signature.
//		//
//		// privKey.D.SetInt64(12345)
//		//
//		return []byte("akljsfjlksafjkaslkfjkasld"), sigType, true, nil
//	}
//	// Notice that the script database parameter is nil here since it isn't
//	// used.  It must be specified when pay-to-script-hash transactions are
//	// being signed.
//	sigScript, err := sign.sign.SignTxOutput(mainNetParams, redeemTx, 0,
//		originTx.TxOut[0].PkScript, txscript.SigHashAll,
//		sign.KeyClosure(lookupKey), nil, nil, noTreasury)
//	if err != nil {
//		fmt.Println(err)
//		return
//	}
//	redeemTx.TxIn[0].SignatureScript = sigScript
//
//	// Prove that the transaction has been validly signed by executing the
//	// script pair.
//
//	flags := txscript.ScriptDiscourageUpgradableNops
//	vm, err := txscript.NewEngine(originTx.TxOut[0].PkScript, redeemTx, 0,
//		flags, 0, nil)
//	if err != nil {
//		fmt.Println(err)
//		return
//	}
//	//fmt.Println()
//	//fmt.Println()
//	//fmt.Println()
//	//var (
//	//	disasmErr error
//	//	i         int
//	//)
//	//for disasmErr == nil {
//	//	disasm, err := vm.DisasmScript(i)
//	//	if err != nil {
//	//		disasmErr = err
//	//	}
//	//	fmt.Println(fmt.Sprintf("%s", disasm))
//	//	i++
//	//}
//	//fmt.Println()
//	//fmt.Println(fmt.Sprintf("FINISHED: %v", disasmErr))
//	if err := vm.Execute(); err != nil {
//		fmt.Println(err)
//		return
//	}
//	fmt.Println("Transaction successfully signed")
//
//	// Output:
//	// Transaction successfully signedddd
//}

func TestSome(t *testing.T) {
	t.Parallel()

	// make key
	// make script based on key.
	// sign with magic pixie dust.
	hashTypes := []txscript.SigHashType{
		txscript.SigHashAll,
		//txscript.SigHashNone,
		//txscript.SigHashSingle,
		//txscript.SigHashAll | txscript.SigHashAnyOneCanPay,
		//txscript.SigHashNone | txscript.SigHashAnyOneCanPay,
		//txscript.SigHashSingle | txscript.SigHashAnyOneCanPay,
	}
	//signatureSuites := []dcrec.SignatureType{
	//	dcrec.STEcdsaSecp256k1,
	//	dcrec.STEd25519,
	//	dcrec.STSchnorrSecp256k1,
	//}
	tx := &wire.MsgTx{
		SerType: wire.TxSerializeFull,
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{},
					Index: 0,
					Tree:  0,
				},
				Sequence:    4294967295,
				ValueIn:     testValueIn,
				BlockHeight: 78901,
				BlockIndex:  23456,
			},
			//{
			//	PreviousOutPoint: wire.OutPoint{
			//		Hash:  chainhash.Hash{},
			//		Index: 1,
			//		Tree:  0,
			//	},
			//	Sequence:    4294967295,
			//	ValueIn:     testValueIn,
			//	BlockHeight: 78901,
			//	BlockIndex:  23456,
			//},
			//{
			//	PreviousOutPoint: wire.OutPoint{
			//		Hash:  chainhash.Hash{},
			//		Index: 2,
			//		Tree:  0,
			//	},
			//	Sequence:    4294967295,
			//	ValueIn:     testValueIn,
			//	BlockHeight: 78901,
			//	BlockIndex:  23456,
			//},
		},
		TxOut: []*wire.TxOut{{
			Version: 0,
			Value:   1,
		}},
		LockTime: 0,
		Expiry:   0,
	}

	//// Pay to Pubkey Hash (uncompressed)
	//for _, hashType := range hashTypes {
	//	for _, suite := range signatureSuites {
	//		for i := range tx.TxIn {
	//			var keyDB []byte
	//
	//			msg := fmt.Sprintf("%d:%d:%d", hashType, i, suite)
	//			var address stdaddr.Address
	//			var err error
	//			switch suite {
	//			case dcrec.STEcdsaSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pkBytes := privKey.PubKey().SerializeUncompressed()
	//				h160 := stdaddr.Hash160(pkBytes)
	//				address, err = stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(
	//					h160, testingParams)
	//
	//			case dcrec.STEd25519:
	//				keyDB, _, _, _ = edwards.GenerateKey(rand.Reader)
	//				_, pk := edwards.PrivKeyFromBytes(keyDB)
	//				pkBytes := pk.SerializeUncompressed()
	//				h160 := stdaddr.Hash160(pkBytes)
	//				address, err = stdaddr.NewAddressPubKeyHashEd25519V0(h160,
	//					testingParams)
	//
	//			case dcrec.STSchnorrSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pkBytes := privKey.PubKey().SerializeCompressed()
	//				h160 := stdaddr.Hash160(pkBytes)
	//				address, err = stdaddr.NewAddressPubKeyHashSchnorrSecp256k1V0(
	//					h160, testingParams)
	//			}
	//			if err != nil {
	//				t.Errorf("failed to make address for %s: %v", msg, err)
	//				break
	//			}
	//
	//			_, pkScript := address.PaymentScript()
	//
	//			// Without treasury agenda.
	//			if err := signAndCheck(msg, tx, i, pkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(nil), noTreasury); err != nil {
	//				t.Error(err)
	//				break
	//			}
	//
	//			if err := signBadAndCheck(msg, tx, i, pkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(nil), noTreasury); err == nil {
	//				t.Errorf("corrupted signature validated: %s", msg)
	//				break
	//			}
	//
	//			// With treasury agenda.
	//			if err := signAndCheck(msg, tx, i, pkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(nil), withTreasury); err != nil {
	//				t.Error(err)
	//				break
	//			}
	//
	//			if err := signBadAndCheck(msg, tx, i, pkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(nil), withTreasury); err == nil {
	//				t.Errorf("corrupted signature validated: %s", msg)
	//				break
	//			}
	//		}
	//	}
	//}
	//
	//// Pay to Pubkey Hash (uncompressed) (merging with correct)
	//for _, hashType := range hashTypes {
	//	for _, suite := range signatureSuites {
	//		for i := range tx.TxIn {
	//			var keyDB []byte
	//
	//			msg := fmt.Sprintf("%d:%d:%d", hashType, i, suite)
	//			var address stdaddr.Address
	//			var err error
	//			switch suite {
	//			case dcrec.STEcdsaSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pkBytes := privKey.PubKey().SerializeUncompressed()
	//				h160 := stdaddr.Hash160(pkBytes)
	//				address, err = stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(
	//					h160, testingParams)
	//
	//			case dcrec.STEd25519:
	//				keyDB, _, _, _ = edwards.GenerateKey(rand.Reader)
	//				_, pk := edwards.PrivKeyFromBytes(keyDB)
	//				pkBytes := pk.SerializeUncompressed()
	//				h160 := stdaddr.Hash160(pkBytes)
	//				address, err = stdaddr.NewAddressPubKeyHashEd25519V0(h160,
	//					testingParams)
	//
	//			case dcrec.STSchnorrSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pkBytes := privKey.PubKey().SerializeCompressed()
	//				h160 := stdaddr.Hash160(pkBytes)
	//				address, err = stdaddr.NewAddressPubKeyHashSchnorrSecp256k1V0(
	//					h160, testingParams)
	//			}
	//			if err != nil {
	//				t.Errorf("failed to make address for %s: %v", msg, err)
	//				break
	//			}
	//
	//			_, pkScript := address.PaymentScript()
	//
	//			// Without treasury agenda.
	//			sigScript, err := sign.SignTxOutput(
	//				testingParams, tx, i, pkScript,
	//				hashType, mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(nil), nil, noTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s: %v", msg,
	//					err)
	//				break
	//			}
	//
	//			// by the above loop, this should be valid, now sign
	//			// again and merge.
	//			sigScript, err = sign.SignTxOutput(
	//				testingParams, tx, i, pkScript,
	//				hashType, mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(nil), sigScript, noTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s a "+
	//					"second time: %v", msg, err)
	//				break
	//			}
	//
	//			err = checkScripts(msg, tx, i, sigScript, pkScript)
	//			if err != nil {
	//				t.Errorf("twice signed script invalid for "+
	//					"%s: %v", msg, err)
	//				break
	//			}
	//
	//			// With treasury agenda.
	//			sigScript, err = sign.SignTxOutput(
	//				testingParams, tx, i, pkScript,
	//				hashType, mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(nil), nil, withTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s: %v", msg,
	//					err)
	//				break
	//			}
	//
	//			// by the above loop, this should be valid, now sign
	//			// again and merge.
	//			sigScript, err = sign.SignTxOutput(
	//				testingParams, tx, i, pkScript,
	//				hashType, mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(nil), sigScript, withTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s a "+
	//					"second time: %v", msg, err)
	//				break
	//			}
	//
	//			err = checkScripts(msg, tx, i, sigScript, pkScript)
	//			if err != nil {
	//				t.Errorf("twice signed script invalid for "+
	//					"%s: %v", msg, err)
	//				break
	//			}
	//		}
	//	}
	//}
	//
	//// Pay to Pubkey Hash (compressed)
	//for _, hashType := range hashTypes {
	//	for _, suite := range signatureSuites {
	//		for i := range tx.TxIn {
	//			var keyDB []byte
	//
	//			msg := fmt.Sprintf("%d:%d:%d", hashType, i, suite)
	//			var address stdaddr.Address
	//			var err error
	//			switch suite {
	//			case dcrec.STEcdsaSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pkBytes := privKey.PubKey().SerializeCompressed()
	//				h160 := stdaddr.Hash160(pkBytes)
	//				address, err = stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(
	//					h160, testingParams)
	//
	//			case dcrec.STEd25519:
	//				keyDB, _, _, _ = edwards.GenerateKey(rand.Reader)
	//				_, pk := edwards.PrivKeyFromBytes(keyDB)
	//				pkBytes := pk.SerializeCompressed()
	//				h160 := stdaddr.Hash160(pkBytes)
	//				address, err = stdaddr.NewAddressPubKeyHashEd25519V0(h160,
	//					testingParams)
	//
	//			case dcrec.STSchnorrSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pkBytes := privKey.PubKey().SerializeCompressed()
	//				h160 := stdaddr.Hash160(pkBytes)
	//				address, err = stdaddr.NewAddressPubKeyHashSchnorrSecp256k1V0(
	//					h160, testingParams)
	//			}
	//			if err != nil {
	//				t.Errorf("failed to make address for %s: %v", msg, err)
	//				break
	//			}
	//
	//			_, pkScript := address.PaymentScript()
	//
	//			// Without treasury agenda.
	//			if err := signAndCheck(msg, tx, i, pkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(nil), noTreasury); err != nil {
	//				t.Error(err)
	//				break
	//			}
	//
	//			if err := signBadAndCheck(msg, tx, i, pkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(nil), noTreasury); err == nil {
	//				t.Errorf("corrupted signature validated: %s", msg)
	//				break
	//			}
	//
	//			// With treasury agenda.
	//			if err := signAndCheck(msg, tx, i, pkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(nil), withTreasury); err != nil {
	//				t.Error(err)
	//				break
	//			}
	//
	//			if err := signBadAndCheck(msg, tx, i, pkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(nil), withTreasury); err == nil {
	//				t.Errorf("corrupted signature validated: %s", msg)
	//				break
	//			}
	//		}
	//	}
	//}
	//
	//// Pay to Pubkey Hash (compressed) with duplicate merge
	//for _, hashType := range hashTypes {
	//	for _, suite := range signatureSuites {
	//		for i := range tx.TxIn {
	//			var keyDB []byte
	//
	//			msg := fmt.Sprintf("%d:%d:%d", hashType, i, suite)
	//			var address stdaddr.Address
	//			var err error
	//			switch suite {
	//			case dcrec.STEcdsaSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pkBytes := privKey.PubKey().SerializeCompressed()
	//				h160 := stdaddr.Hash160(pkBytes)
	//				address, err = stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(
	//					h160, testingParams)
	//
	//			case dcrec.STEd25519:
	//				keyDB, _, _, _ = edwards.GenerateKey(rand.Reader)
	//				_, pk := edwards.PrivKeyFromBytes(keyDB)
	//				pkBytes := pk.SerializeCompressed()
	//				h160 := stdaddr.Hash160(pkBytes)
	//				address, err = stdaddr.NewAddressPubKeyHashEd25519V0(h160,
	//					testingParams)
	//
	//			case dcrec.STSchnorrSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pkBytes := privKey.PubKey().SerializeCompressed()
	//				h160 := stdaddr.Hash160(pkBytes)
	//				address, err = stdaddr.NewAddressPubKeyHashSchnorrSecp256k1V0(
	//					h160, testingParams)
	//			}
	//			if err != nil {
	//				t.Errorf("failed to make address for %s: %v", msg, err)
	//				break
	//			}
	//
	//			_, pkScript := address.PaymentScript()
	//
	//			// Without treasury agenda.
	//			sigScript, err := sign.SignTxOutput(testingParams,
	//				tx, i, pkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(nil), nil, noTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s: %v", msg,
	//					err)
	//				break
	//			}
	//
	//			// by the above loop, this should be valid, now sign
	//			// again and merge.
	//			sigScript, err = sign.SignTxOutput(testingParams,
	//				tx, i, pkScript,
	//				hashType, mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(nil), sigScript, noTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s a "+
	//					"second time: %v", msg, err)
	//				break
	//			}
	//
	//			err = checkScripts(msg, tx, i, sigScript, pkScript)
	//			if err != nil {
	//				t.Errorf("twice signed script invalid for "+
	//					"%s: %v", msg, err)
	//				break
	//			}
	//
	//			// With treasury agenda.
	//			sigScript, err = sign.SignTxOutput(testingParams,
	//				tx, i, pkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(nil), nil, withTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s: %v", msg,
	//					err)
	//				break
	//			}
	//
	//			// by the above loop, this should be valid, now sign
	//			// again and merge.
	//			sigScript, err = sign.SignTxOutput(testingParams,
	//				tx, i, pkScript,
	//				hashType, mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(nil), sigScript, withTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s a "+
	//					"second time: %v", msg, err)
	//				break
	//			}
	//
	//			err = checkScripts(msg, tx, i, sigScript, pkScript)
	//			if err != nil {
	//				t.Errorf("twice signed script invalid for "+
	//					"%s: %v", msg, err)
	//				break
	//			}
	//		}
	//	}
	//}
	//
	//// Pay to Pubkey Hash for a ticket(SStx) (compressed)
	//for _, hashType := range hashTypes {
	//	for i := range tx.TxIn {
	//		msg := fmt.Sprintf("%d:%d", hashType, i)
	//
	//		privKey, err := secp256k1.GeneratePrivateKey()
	//		if err != nil {
	//			t.Errorf("failed to generate key: %v", err)
	//			break
	//		}
	//		keyDB := privKey.Serialize()
	//		pkBytes := privKey.PubKey().SerializeCompressed()
	//
	//		address, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(
	//			stdaddr.Hash160(pkBytes), testingParams)
	//		if err != nil {
	//			t.Errorf("failed to make address for %s: %v", msg, err)
	//		}
	//
	//		_, pkScript := address.VotingRightsScript()
	//
	//		// Without treasury agenda.
	//		suite := dcrec.STEcdsaSecp256k1
	//		if err := signAndCheck(msg, tx, i, pkScript, hashType,
	//			mkGetKey(map[string]addressToKey{
	//				address.String(): {keyDB, suite, true},
	//			}), mkGetScript(nil), noTreasury); err != nil {
	//			t.Error(err)
	//			break
	//		}
	//
	//		if err := signBadAndCheck(msg, tx, i, pkScript, hashType,
	//			mkGetKey(map[string]addressToKey{
	//				address.String(): {keyDB, suite, true},
	//			}), mkGetScript(nil), noTreasury); err == nil {
	//			t.Errorf("corrupted signature validated: %s", msg)
	//			break
	//		}
	//
	//		// With treasury agenda.
	//		if err := signAndCheck(msg, tx, i, pkScript, hashType,
	//			mkGetKey(map[string]addressToKey{
	//				address.String(): {keyDB, suite, true},
	//			}), mkGetScript(nil), withTreasury); err != nil {
	//			t.Error(err)
	//			break
	//		}
	//
	//		if err := signBadAndCheck(msg, tx, i, pkScript, hashType,
	//			mkGetKey(map[string]addressToKey{
	//				address.String(): {keyDB, suite, true},
	//			}), mkGetScript(nil), withTreasury); err == nil {
	//			t.Errorf("corrupted signature validated: %s", msg)
	//			break
	//		}
	//	}
	//}
	//
	//// Pay to Pubkey Hash for a ticket change (SStx change) (compressed)
	//for _, hashType := range hashTypes {
	//	for i := range tx.TxIn {
	//		msg := fmt.Sprintf("%d:%d", hashType, i)
	//
	//		privKey, err := secp256k1.GeneratePrivateKey()
	//		if err != nil {
	//			t.Errorf("failed to generate key: %v", err)
	//			break
	//		}
	//		keyDB := privKey.Serialize()
	//		pkBytes := privKey.PubKey().SerializeCompressed()
	//
	//		address, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(
	//			stdaddr.Hash160(pkBytes), testingParams)
	//		if err != nil {
	//			t.Errorf("failed to make address for %s: %v", msg, err)
	//			break
	//		}
	//
	//		_, pkScript := address.StakeChangeScript()
	//
	//		// Without treasury agenda.
	//		suite := dcrec.STEcdsaSecp256k1
	//		if err := signAndCheck(msg, tx, i, pkScript, hashType,
	//			mkGetKey(map[string]addressToKey{
	//				address.String(): {keyDB, suite, true},
	//			}), mkGetScript(nil), noTreasury); err != nil {
	//			t.Error(err)
	//			break
	//		}
	//
	//		if err := signBadAndCheck(msg, tx, i, pkScript, hashType,
	//			mkGetKey(map[string]addressToKey{
	//				address.String(): {keyDB, suite, true},
	//			}), mkGetScript(nil), noTreasury); err == nil {
	//			t.Errorf("corrupted signature validated: %s", msg)
	//			break
	//		}
	//
	//		// With treasury agenda.
	//		if err := signAndCheck(msg, tx, i, pkScript, hashType,
	//			mkGetKey(map[string]addressToKey{
	//				address.String(): {keyDB, suite, true},
	//			}), mkGetScript(nil), withTreasury); err != nil {
	//			t.Error(err)
	//			break
	//		}
	//
	//		if err := signBadAndCheck(msg, tx, i, pkScript, hashType,
	//			mkGetKey(map[string]addressToKey{
	//				address.String(): {keyDB, suite, true},
	//			}), mkGetScript(nil), withTreasury); err == nil {
	//			t.Errorf("corrupted signature validated: %s", msg)
	//			break
	//		}
	//	}
	//}
	//
	//// Pay to Pubkey Hash for a ticket spending (SSGen) (compressed)
	//for _, hashType := range hashTypes {
	//	for i := range tx.TxIn {
	//		msg := fmt.Sprintf("%d:%d", hashType, i)
	//
	//		privKey, err := secp256k1.GeneratePrivateKey()
	//		if err != nil {
	//			t.Errorf("failed to generate key: %v", err)
	//			break
	//		}
	//		keyDB := privKey.Serialize()
	//		pkBytes := privKey.PubKey().SerializeCompressed()
	//
	//		address, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(
	//			stdaddr.Hash160(pkBytes), testingParams)
	//		if err != nil {
	//			t.Errorf("failed to make address for %s: %v", msg, err)
	//			break
	//		}
	//
	//		_, pkScript := address.PayVoteCommitmentScript()
	//
	//		// Without treasury agenda.
	//		suite := dcrec.STEcdsaSecp256k1
	//		if err := signAndCheck(msg, tx, i, pkScript, hashType,
	//			mkGetKey(map[string]addressToKey{
	//				address.String(): {keyDB, suite, true},
	//			}), mkGetScript(nil), noTreasury); err != nil {
	//			t.Error(err)
	//			break
	//		}
	//
	//		if err := signBadAndCheck(msg, tx, i, pkScript, hashType,
	//			mkGetKey(map[string]addressToKey{
	//				address.String(): {keyDB, suite, true},
	//			}), mkGetScript(nil), noTreasury); err == nil {
	//			t.Errorf("corrupted signature validated: %s", msg)
	//			break
	//		}
	//
	//		// With treasury agenda.
	//		if err := signAndCheck(msg, tx, i, pkScript, hashType,
	//			mkGetKey(map[string]addressToKey{
	//				address.String(): {keyDB, suite, true},
	//			}), mkGetScript(nil), withTreasury); err != nil {
	//			t.Error(err)
	//			break
	//		}
	//
	//		if err := signBadAndCheck(msg, tx, i, pkScript, hashType,
	//			mkGetKey(map[string]addressToKey{
	//				address.String(): {keyDB, suite, true},
	//			}), mkGetScript(nil), withTreasury); err == nil {
	//			t.Errorf("corrupted signature validated: %s", msg)
	//			break
	//		}
	//	}
	//}
	//
	//// Pay to Pubkey Hash for a ticket revocation (SSRtx) (compressed)
	//for _, hashType := range hashTypes {
	//	for i := range tx.TxIn {
	//		msg := fmt.Sprintf("%d:%d", hashType, i)
	//
	//		privKey, err := secp256k1.GeneratePrivateKey()
	//		if err != nil {
	//			t.Errorf("failed to generate key: %v", err)
	//			break
	//		}
	//		keyDB := privKey.Serialize()
	//		pkBytes := privKey.PubKey().SerializeCompressed()
	//
	//		address, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(
	//			stdaddr.Hash160(pkBytes), testingParams)
	//		if err != nil {
	//			t.Errorf("failed to make address for %s: %v",
	//				msg, err)
	//			break
	//		}
	//
	//		_, pkScript := address.PayRevokeCommitmentScript()
	//
	//		// Without treasury agenda.
	//		suite := dcrec.STEcdsaSecp256k1
	//		if err := signAndCheck(msg, tx, i, pkScript, hashType,
	//			mkGetKey(map[string]addressToKey{
	//				address.String(): {keyDB, suite, true},
	//			}), mkGetScript(nil), noTreasury); err != nil {
	//			t.Error(err)
	//			break
	//		}
	//
	//		if err := signBadAndCheck(msg, tx, i, pkScript, hashType,
	//			mkGetKey(map[string]addressToKey{
	//				address.String(): {keyDB, suite, true},
	//			}), mkGetScript(nil), noTreasury); err == nil {
	//			t.Errorf("corrupted signature validated: %s", msg)
	//			break
	//		}
	//
	//		// With treasury agenda.
	//		if err := signAndCheck(msg, tx, i, pkScript, hashType,
	//			mkGetKey(map[string]addressToKey{
	//				address.String(): {keyDB, suite, true},
	//			}), mkGetScript(nil), withTreasury); err != nil {
	//			t.Error(err)
	//			break
	//		}
	//
	//		if err := signBadAndCheck(msg, tx, i, pkScript, hashType,
	//			mkGetKey(map[string]addressToKey{
	//				address.String(): {keyDB, suite, true},
	//			}), mkGetScript(nil), withTreasury); err == nil {
	//			t.Errorf("corrupted signature validated: %s", msg)
	//			break
	//		}
	//	}
	//}
	//
	//// Pay to PubKey (uncompressed)
	//for _, hashType := range hashTypes {
	//	for i := range tx.TxIn {
	//		msg := fmt.Sprintf("%d:%d", hashType, i)
	//
	//		privKey, err := secp256k1.GeneratePrivateKey()
	//		if err != nil {
	//			t.Errorf("failed to generate key: %v", err)
	//			break
	//		}
	//		keyDB := privKey.Serialize()
	//		pk := privKey.PubKey()
	//		address, err := stdaddr.NewAddressPubKeyEcdsaSecp256k1V0(pk,
	//			testingParams)
	//		if err != nil {
	//			t.Errorf("failed to make address for %s: %v", msg, err)
	//			break
	//		}
	//
	//		_, pkScript := address.PaymentScript()
	//
	//		// Without treasury agenda.
	//		suite := dcrec.STEcdsaSecp256k1
	//		if err := signAndCheck(msg, tx, i, pkScript, hashType,
	//			mkGetKey(map[string]addressToKey{
	//				address.String(): {keyDB, suite, false},
	//			}), mkGetScript(nil), noTreasury); err != nil {
	//			t.Error(err)
	//			break
	//		}
	//
	//		if err := signBadAndCheck(msg, tx, i, pkScript, hashType,
	//			mkGetKey(map[string]addressToKey{
	//				address.String(): {keyDB, dcrec.STEcdsaSecp256k1, false},
	//			}), mkGetScript(nil), noTreasury); err == nil {
	//			t.Errorf("corrupted signature validated: %s", msg)
	//			break
	//		}
	//
	//		// With treasury agenda.
	//		if err := signAndCheck(msg, tx, i, pkScript, hashType,
	//			mkGetKey(map[string]addressToKey{
	//				address.String(): {keyDB, suite, false},
	//			}), mkGetScript(nil), withTreasury); err != nil {
	//			t.Error(err)
	//			break
	//		}
	//
	//		if err := signBadAndCheck(msg, tx, i, pkScript, hashType,
	//			mkGetKey(map[string]addressToKey{
	//				address.String(): {keyDB, dcrec.STEcdsaSecp256k1, false},
	//			}), mkGetScript(nil), withTreasury); err == nil {
	//			t.Errorf("corrupted signature validated: %s", msg)
	//			break
	//		}
	//	}
	//}
	//
	//// Pay to PubKey (uncompressed)
	//for _, hashType := range hashTypes {
	//	for _, suite := range signatureSuites {
	//		for i := range tx.TxIn {
	//			var keyDB []byte
	//
	//			msg := fmt.Sprintf("%d:%d:%d", hashType, i, suite)
	//			var address stdaddr.Address
	//			var err error
	//			switch suite {
	//			case dcrec.STEcdsaSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pk := privKey.PubKey()
	//				address, err = stdaddr.NewAddressPubKeyEcdsaSecp256k1V0(pk,
	//					testingParams)
	//				if err != nil {
	//					t.Errorf("failed to make address for %s: %v", msg, err)
	//				}
	//
	//			case dcrec.STEd25519:
	//				keyDB, _, _, _ = edwards.GenerateKey(rand.Reader)
	//				_, pk := edwards.PrivKeyFromBytes(keyDB)
	//				pkBytes := pk.SerializeUncompressed()
	//				address, err = stdaddr.NewAddressPubKeyEd25519V0Raw(pkBytes,
	//					testingParams)
	//				if err != nil {
	//					t.Errorf("failed to make address for %s: %v", msg, err)
	//				}
	//
	//			case dcrec.STSchnorrSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pk := privKey.PubKey()
	//				address, err = stdaddr.NewAddressPubKeySchnorrSecp256k1V0(pk,
	//					testingParams)
	//				if err != nil {
	//					t.Errorf("failed to make address for %s: %v", msg, err)
	//				}
	//			}
	//
	//			_, pkScript := address.PaymentScript()
	//
	//			// Without treasury agenda.
	//			sigScript, err := sign.SignTxOutput(testingParams,
	//				tx, i, pkScript, hashType,
	//				mkGetKeyPub(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(nil), nil, noTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s: %v", msg,
	//					err)
	//			}
	//
	//			// by the above loop, this should be valid, now sign
	//			// again and merge.
	//			sigScript, err = sign.SignTxOutput(testingParams,
	//				tx, i, pkScript, hashType,
	//				mkGetKeyPub(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(nil), sigScript, noTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s a "+
	//					"second time: %v", msg, err)
	//			}
	//
	//			err = checkScripts(msg, tx, i, sigScript, pkScript)
	//			if err != nil {
	//				t.Errorf("twice signed script invalid for "+
	//					"%s: %v", msg, err)
	//			}
	//
	//			// With treasury agenda.
	//			sigScript, err = sign.SignTxOutput(testingParams,
	//				tx, i, pkScript, hashType,
	//				mkGetKeyPub(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(nil), nil, withTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s: %v", msg,
	//					err)
	//			}
	//
	//			// by the above loop, this should be valid, now sign
	//			// again and merge.
	//			sigScript, err = sign.SignTxOutput(testingParams,
	//				tx, i, pkScript, hashType,
	//				mkGetKeyPub(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(nil), sigScript, withTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s a "+
	//					"second time: %v", msg, err)
	//			}
	//
	//			err = checkScripts(msg, tx, i, sigScript, pkScript)
	//			if err != nil {
	//				t.Errorf("twice signed script invalid for "+
	//					"%s: %v", msg, err)
	//			}
	//		}
	//	}
	//}
	//
	//// Pay to PubKey (compressed)
	//for _, hashType := range hashTypes {
	//	for _, suite := range signatureSuites {
	//		for i := range tx.TxIn {
	//			var keyDB []byte
	//
	//			msg := fmt.Sprintf("%d:%d:%d", hashType, i, suite)
	//			var address stdaddr.Address
	//			var err error
	//			switch suite {
	//			case dcrec.STEcdsaSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pk := privKey.PubKey()
	//				address, err = stdaddr.NewAddressPubKeyEcdsaSecp256k1V0(pk,
	//					testingParams)
	//				if err != nil {
	//					t.Errorf("failed to make address for %s: %v", msg, err)
	//				}
	//
	//			case dcrec.STEd25519:
	//				keyDB, _, _, _ = edwards.GenerateKey(rand.Reader)
	//				_, pk := edwards.PrivKeyFromBytes(keyDB)
	//				pkBytes := pk.SerializeCompressed()
	//				address, err = stdaddr.NewAddressPubKeyEd25519V0Raw(pkBytes,
	//					testingParams)
	//				if err != nil {
	//					t.Errorf("failed to make address for %s: %v", msg, err)
	//				}
	//
	//			case dcrec.STSchnorrSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pk := privKey.PubKey()
	//				address, err = stdaddr.NewAddressPubKeySchnorrSecp256k1V0(pk,
	//					testingParams)
	//				if err != nil {
	//					t.Errorf("failed to make address for %s: %v", msg, err)
	//				}
	//			}
	//
	//			_, pkScript := address.PaymentScript()
	//
	//			// Without treasury agenda.
	//			if err := signAndCheck(msg, tx, i, pkScript, hashType,
	//				mkGetKeyPub(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(nil), noTreasury); err != nil {
	//				t.Error(err)
	//				break
	//			}
	//
	//			if err := signBadAndCheck(msg, tx, i, pkScript, hashType,
	//				mkGetKeyPub(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(nil), noTreasury); err == nil {
	//				t.Errorf("corrupted signature validated: %s", msg)
	//				break
	//			}
	//
	//			// With treasury agenda.
	//			if err := signAndCheck(msg, tx, i, pkScript, hashType,
	//				mkGetKeyPub(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(nil), withTreasury); err != nil {
	//				t.Error(err)
	//				break
	//			}
	//
	//			if err := signBadAndCheck(msg, tx, i, pkScript, hashType,
	//				mkGetKeyPub(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(nil), withTreasury); err == nil {
	//				t.Errorf("corrupted signature validated: %s", msg)
	//				break
	//			}
	//		}
	//	}
	//}
	//
	//// Pay to PubKey (compressed) with duplicate merge
	//for _, hashType := range hashTypes {
	//	for _, suite := range signatureSuites {
	//		for i := range tx.TxIn {
	//			var keyDB []byte
	//
	//			msg := fmt.Sprintf("%d:%d:%d", hashType, i, suite)
	//			var address stdaddr.Address
	//			var err error
	//			switch suite {
	//			case dcrec.STEcdsaSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pk := privKey.PubKey()
	//				address, err = stdaddr.NewAddressPubKeyEcdsaSecp256k1V0(pk,
	//					testingParams)
	//				if err != nil {
	//					t.Errorf("failed to make address for %s: %v", msg, err)
	//				}
	//
	//			case dcrec.STEd25519:
	//				keyDB, _, _, _ = edwards.GenerateKey(rand.Reader)
	//				_, pk := edwards.PrivKeyFromBytes(keyDB)
	//				pkBytes := pk.SerializeCompressed()
	//				address, err = stdaddr.NewAddressPubKeyEd25519V0Raw(pkBytes,
	//					testingParams)
	//				if err != nil {
	//					t.Errorf("failed to make address for %s: %v", msg, err)
	//				}
	//
	//			case dcrec.STSchnorrSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pk := privKey.PubKey()
	//				address, err = stdaddr.NewAddressPubKeySchnorrSecp256k1V0(pk,
	//					testingParams)
	//				if err != nil {
	//					t.Errorf("failed to make address for %s: %v", msg, err)
	//				}
	//			}
	//
	//			_, pkScript := address.PaymentScript()
	//
	//			// Without treasury agenda.
	//			sigScript, err := sign.SignTxOutput(testingParams,
	//				tx, i, pkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(nil), nil, noTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s: %v", msg,
	//					err)
	//				break
	//			}
	//
	//			// by the above loop, this should be valid, now sign
	//			// again and merge.
	//			sigScript, err = sign.SignTxOutput(testingParams,
	//				tx, i, pkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(nil), sigScript, noTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s a "+
	//					"second time: %v", msg, err)
	//				break
	//			}
	//
	//			err = checkScripts(msg, tx, i, sigScript, pkScript)
	//			if err != nil {
	//				t.Errorf("twice signed script invalid for "+
	//					"%s: %v", msg, err)
	//				break
	//			}
	//
	//			// With treasury agenda.
	//			sigScript, err = sign.SignTxOutput(testingParams,
	//				tx, i, pkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(nil), nil, withTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s: %v", msg,
	//					err)
	//				break
	//			}
	//
	//			// by the above loop, this should be valid, now sign
	//			// again and merge.
	//			sigScript, err = sign.SignTxOutput(testingParams,
	//				tx, i, pkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(nil), sigScript, withTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s a "+
	//					"second time: %v", msg, err)
	//				break
	//			}
	//
	//			err = checkScripts(msg, tx, i, sigScript, pkScript)
	//			if err != nil {
	//				t.Errorf("twice signed script invalid for "+
	//					"%s: %v", msg, err)
	//				break
	//			}
	//		}
	//	}
	//}

	//// As before, but with p2sh now.
	//// Pay to Pubkey Hash (uncompressed)
	//for _, hashType := range hashTypes {
	//	for _, suite := range signatureSuites {
	//		for i := range tx.TxIn {
	//			var keyDB []byte
	//
	//			msg := fmt.Sprintf("%d:%d:%d", hashType, i, suite)
	//			var address stdaddr.Address
	//			var err error
	//			switch suite {
	//			case dcrec.STEcdsaSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pkBytes := privKey.PubKey().SerializeUncompressed()
	//				h160 := stdaddr.Hash160(pkBytes)
	//				address, err = stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(
	//					h160, testingParams)
	//
	//			case dcrec.STEd25519:
	//				keyDB, _, _, _ = edwards.GenerateKey(rand.Reader)
	//				_, pk := edwards.PrivKeyFromBytes(keyDB)
	//				pkBytes := pk.SerializeUncompressed()
	//				h160 := stdaddr.Hash160(pkBytes)
	//				address, err = stdaddr.NewAddressPubKeyHashEd25519V0(h160,
	//					testingParams)
	//
	//			case dcrec.STSchnorrSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pkBytes := privKey.PubKey().SerializeCompressed()
	//				h160 := stdaddr.Hash160(pkBytes)
	//				address, err = stdaddr.NewAddressPubKeyHashSchnorrSecp256k1V0(
	//					h160, testingParams)
	//			}
	//			if err != nil {
	//				t.Errorf("failed to make address for %s: %v", msg, err)
	//				break
	//			}
	//
	//			_, pkScript := address.PaymentScript()
	//
	//			scriptAddr, err := stdaddr.NewAddressScriptHashV0(pkScript,
	//				testingParams)
	//			if err != nil {
	//				t.Errorf("failed to make p2sh addr for %s: %v", msg, err)
	//				break
	//			}
	//
	//			_, scriptPkScript := scriptAddr.PaymentScript()
	//
	//			// Without treasury agenda.
	//			if err := signAndCheck(msg, tx, i, scriptPkScript,
	//				hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(map[string][]byte{
	//					scriptAddr.String(): pkScript,
	//				}), noTreasury); err != nil {
	//				t.Error(err)
	//				break
	//			}
	//
	//			if err := signBadAndCheck(msg, tx, i, pkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(nil), noTreasury); err == nil {
	//				t.Errorf("corrupted signature validated: %s", msg)
	//				break
	//			}
	//
	//			// With treasury agenda.
	//			if err := signAndCheck(msg, tx, i, scriptPkScript,
	//				hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(map[string][]byte{
	//					scriptAddr.String(): pkScript,
	//				}), withTreasury); err != nil {
	//				t.Error(err)
	//				break
	//			}
	//
	//			if err := signBadAndCheck(msg, tx, i, pkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(nil), withTreasury); err == nil {
	//				t.Errorf("corrupted signature validated: %s", msg)
	//				break
	//			}
	//		}
	//	}
	//}

	//// Pay to Pubkey Hash (uncompressed) with duplicate merge
	//for _, hashType := range hashTypes {
	//	for _, suite := range signatureSuites {
	//		for i := range tx.TxIn {
	//			var keyDB []byte
	//
	//			msg := fmt.Sprintf("%d:%d:%d", hashType, i, suite)
	//			var address stdaddr.Address
	//			var err error
	//			switch suite {
	//			case dcrec.STEcdsaSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pkBytes := privKey.PubKey().SerializeUncompressed()
	//				h160 := stdaddr.Hash160(pkBytes)
	//				address, err = stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(
	//					h160, testingParams)
	//
	//			case dcrec.STEd25519:
	//				keyDB, _, _, _ = edwards.GenerateKey(rand.Reader)
	//				_, pk := edwards.PrivKeyFromBytes(keyDB)
	//				pkBytes := pk.SerializeUncompressed()
	//				h160 := stdaddr.Hash160(pkBytes)
	//				address, err = stdaddr.NewAddressPubKeyHashEd25519V0(h160,
	//					testingParams)
	//
	//			case dcrec.STSchnorrSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pkBytes := privKey.PubKey().SerializeCompressed()
	//				h160 := stdaddr.Hash160(pkBytes)
	//				address, err = stdaddr.NewAddressPubKeyHashSchnorrSecp256k1V0(
	//					h160, testingParams)
	//			}
	//			if err != nil {
	//				t.Errorf("failed to make address for %s: %v", msg, err)
	//				break
	//			}
	//
	//			_, pkScript := address.PaymentScript()
	//
	//			scriptAddr, err := stdaddr.NewAddressScriptHashV0(pkScript,
	//				testingParams)
	//			if err != nil {
	//				t.Errorf("failed to make p2sh addr for %s: %v", msg, err)
	//				break
	//			}
	//
	//			_, scriptPkScript := scriptAddr.PaymentScript()
	//
	//			// Without treasury agenda.
	//			_, err = sign.SignTxOutput(testingParams, tx, i,
	//				scriptPkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(map[string][]byte{
	//					scriptAddr.String(): pkScript}), nil, noTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s: %v", msg,
	//					err)
	//				break
	//			}
	//
	//			// by the above loop, this should be valid, now sign
	//			// again and merge.
	//			sigScript, err := sign.SignTxOutput(testingParams,
	//				tx, i, scriptPkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(map[string][]byte{
	//					scriptAddr.String(): pkScript,
	//				}), nil, noTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s a "+
	//					"second time: %v", msg, err)
	//				break
	//			}
	//
	//			err = checkScripts(msg, tx, i, sigScript, scriptPkScript)
	//			if err != nil {
	//				t.Errorf("twice signed script invalid for "+
	//					"%s: %v", msg, err)
	//				break
	//			}
	//
	//			// Wit treasury agenda.
	//			_, err = sign.SignTxOutput(testingParams, tx, i,
	//				scriptPkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(map[string][]byte{
	//					scriptAddr.String(): pkScript}), nil, withTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s: %v", msg,
	//					err)
	//				break
	//			}
	//
	//			// by the above loop, this should be valid, now sign
	//			// again and merge.
	//			sigScript, err = sign.SignTxOutput(testingParams,
	//				tx, i, scriptPkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(map[string][]byte{
	//					scriptAddr.String(): pkScript,
	//				}), nil, withTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s a "+
	//					"second time: %v", msg, err)
	//				break
	//			}
	//
	//			err = checkScripts(msg, tx, i, sigScript, scriptPkScript)
	//			if err != nil {
	//				t.Errorf("twice signed script invalid for "+
	//					"%s: %v", msg, err)
	//				break
	//			}
	//		}
	//	}
	//}

	//// Pay to Pubkey Hash (compressed)
	//for _, hashType := range hashTypes {
	//	for _, suite := range signatureSuites {
	//		for i := range tx.TxIn {
	//			var keyDB []byte
	//
	//			msg := fmt.Sprintf("%d:%d:%d", hashType, i, suite)
	//			var address stdaddr.Address
	//			var err error
	//			switch suite {
	//			case dcrec.STEcdsaSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pkBytes := privKey.PubKey().SerializeCompressed()
	//				h160 := stdaddr.Hash160(pkBytes)
	//				address, err = stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(
	//					h160, testingParams)
	//
	//			case dcrec.STEd25519:
	//				keyDB, _, _, _ = edwards.GenerateKey(rand.Reader)
	//				_, pk := edwards.PrivKeyFromBytes(keyDB)
	//				pkBytes := pk.SerializeCompressed()
	//				h160 := stdaddr.Hash160(pkBytes)
	//				address, err = stdaddr.NewAddressPubKeyHashEd25519V0(h160,
	//					testingParams)
	//
	//			case dcrec.STSchnorrSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pkBytes := privKey.PubKey().SerializeCompressed()
	//				h160 := stdaddr.Hash160(pkBytes)
	//				address, err = stdaddr.NewAddressPubKeyHashSchnorrSecp256k1V0(
	//					h160, testingParams)
	//			}
	//			if err != nil {
	//				t.Errorf("failed to make address for %s: %v", msg, err)
	//				break
	//			}
	//
	//			_, pkScript := address.PaymentScript()
	//
	//			scriptAddr, err := stdaddr.NewAddressScriptHashV0(pkScript,
	//				testingParams)
	//			if err != nil {
	//				t.Errorf("failed to make p2sh addr for %s: %v", msg, err)
	//				break
	//			}
	//
	//			_, scriptPkScript := scriptAddr.PaymentScript()
	//
	//			// Without treasury agenda.
	//			if err := signAndCheck(msg, tx, i, scriptPkScript,
	//				hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(map[string][]byte{
	//					scriptAddr.String(): pkScript,
	//				}), noTreasury); err != nil {
	//				t.Error(err)
	//				break
	//			}
	//
	//			if err := signBadAndCheck(msg, tx, i, pkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(nil), noTreasury); err == nil {
	//				t.Errorf("corrupted signature validated: %s", msg)
	//				break
	//			}
	//
	//			// With treasury agenda.
	//			if err := signAndCheck(msg, tx, i, scriptPkScript,
	//				hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(map[string][]byte{
	//					scriptAddr.String(): pkScript,
	//				}), withTreasury); err != nil {
	//				t.Error(err)
	//				break
	//			}
	//
	//			if err := signBadAndCheck(msg, tx, i, pkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(nil), withTreasury); err == nil {
	//				t.Errorf("corrupted signature validated: %s", msg)
	//				break
	//			}
	//		}
	//	}
	//}

	//// Pay to Pubkey Hash (compressed) with duplicate merge
	//for _, hashType := range hashTypes {
	//	for _, suite := range signatureSuites {
	//		for i := range tx.TxIn {
	//			var keyDB []byte
	//
	//			msg := fmt.Sprintf("%d:%d:%d", hashType, i, suite)
	//			var address stdaddr.Address
	//			var err error
	//			switch suite {
	//			case dcrec.STEcdsaSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pkBytes := privKey.PubKey().SerializeCompressed()
	//				h160 := stdaddr.Hash160(pkBytes)
	//				address, err = stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(
	//					h160, testingParams)
	//
	//			case dcrec.STEd25519:
	//				keyDB, _, _, _ = edwards.GenerateKey(rand.Reader)
	//				_, pk := edwards.PrivKeyFromBytes(keyDB)
	//				pkBytes := pk.SerializeCompressed()
	//				h160 := stdaddr.Hash160(pkBytes)
	//				address, err = stdaddr.NewAddressPubKeyHashEd25519V0(h160,
	//					testingParams)
	//
	//			case dcrec.STSchnorrSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pkBytes := privKey.PubKey().SerializeCompressed()
	//				h160 := stdaddr.Hash160(pkBytes)
	//				address, err = stdaddr.NewAddressPubKeyHashSchnorrSecp256k1V0(
	//					h160, testingParams)
	//			}
	//			if err != nil {
	//				t.Errorf("failed to make address for %s: %v", msg, err)
	//				break
	//			}
	//
	//			_, pkScript := address.PaymentScript()
	//
	//			scriptAddr, err := stdaddr.NewAddressScriptHashV0(pkScript,
	//				testingParams)
	//			if err != nil {
	//				t.Errorf("failed to make p2sh addr for %s: %v", msg, err)
	//				break
	//			}
	//
	//			_, scriptPkScript := scriptAddr.PaymentScript()
	//
	//			// Without treasury agenda.
	//			_, err = sign.SignTxOutput(testingParams,
	//				tx, i, scriptPkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(map[string][]byte{
	//					scriptAddr.String(): pkScript,
	//				}), nil, noTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s: %v", msg,
	//					err)
	//				break
	//			}
	//
	//			// by the above loop, this should be valid, now sign
	//			// again and merge.
	//			sigScript, err := sign.SignTxOutput(testingParams,
	//				tx, i, scriptPkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(map[string][]byte{
	//					scriptAddr.String(): pkScript,
	//				}), nil, noTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s a "+
	//					"second time: %v", msg, err)
	//				break
	//			}
	//
	//			err = checkScripts(msg, tx, i, sigScript, scriptPkScript)
	//			if err != nil {
	//				t.Errorf("twice signed script invalid for "+
	//					"%s: %v", msg, err)
	//				break
	//			}
	//
	//			// With treasury agenda.
	//			_, err = sign.SignTxOutput(testingParams,
	//				tx, i, scriptPkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(map[string][]byte{
	//					scriptAddr.String(): pkScript,
	//				}), nil, withTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s: %v", msg,
	//					err)
	//				break
	//			}
	//
	//			// by the above loop, this should be valid, now sign
	//			// again and merge.
	//			sigScript, err = sign.SignTxOutput(testingParams,
	//				tx, i, scriptPkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(map[string][]byte{
	//					scriptAddr.String(): pkScript,
	//				}), nil, withTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s a "+
	//					"second time: %v", msg, err)
	//				break
	//			}
	//
	//			err = checkScripts(msg, tx, i, sigScript, scriptPkScript)
	//			if err != nil {
	//				t.Errorf("twice signed script invalid for "+
	//					"%s: %v", msg, err)
	//				break
	//			}
	//		}
	//	}
	//}

	//// Pay to PubKey (uncompressed)
	//for _, hashType := range hashTypes {
	//	for _, suite := range signatureSuites {
	//		for i := range tx.TxIn {
	//			var keyDB []byte
	//
	//			msg := fmt.Sprintf("%d:%d:%d", hashType, i, suite)
	//			var address stdaddr.Address
	//			var err error
	//			switch suite {
	//			case dcrec.STEcdsaSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pk := privKey.PubKey()
	//				address, err = stdaddr.NewAddressPubKeyEcdsaSecp256k1V0(pk,
	//					testingParams)
	//
	//			case dcrec.STEd25519:
	//				keyDB, _, _, _ = edwards.GenerateKey(rand.Reader)
	//				_, pk := edwards.PrivKeyFromBytes(keyDB)
	//				pkBytes := pk.SerializeUncompressed()
	//				address, err = stdaddr.NewAddressPubKeyEd25519V0Raw(pkBytes,
	//					testingParams)
	//
	//			case dcrec.STSchnorrSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pk := privKey.PubKey()
	//				address, err = stdaddr.NewAddressPubKeySchnorrSecp256k1V0(pk,
	//					testingParams)
	//			}
	//			if err != nil {
	//				t.Errorf("failed to make address for %s: %v", msg, err)
	//				break
	//			}
	//
	//			_, pkScript := address.PaymentScript()
	//
	//			scriptAddr, err := stdaddr.NewAddressScriptHashV0(pkScript,
	//				testingParams)
	//			if err != nil {
	//				t.Errorf("failed to make p2sh addr for %s: %v", msg, err)
	//			}
	//
	//			_, scriptPkScript := scriptAddr.PaymentScript()
	//
	//			// Without treasury agenda.
	//			if err := signAndCheck(msg, tx, i, scriptPkScript,
	//				hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(map[string][]byte{
	//					scriptAddr.String(): pkScript,
	//				}), noTreasury); err != nil {
	//				t.Error(err)
	//			}
	//
	//			if err := signBadAndCheck(msg, tx, i, pkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(nil), noTreasury); err == nil {
	//				t.Errorf("corrupted signature validated: %s", msg)
	//				break
	//			}
	//
	//			// With treasury agenda.
	//			if err := signAndCheck(msg, tx, i, scriptPkScript,
	//				hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(map[string][]byte{
	//					scriptAddr.String(): pkScript,
	//				}), withTreasury); err != nil {
	//				t.Error(err)
	//			}
	//
	//			if err := signBadAndCheck(msg, tx, i, pkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(nil), withTreasury); err == nil {
	//				t.Errorf("corrupted signature validated: %s", msg)
	//				break
	//			}
	//		}
	//	}
	//}
	//
	//// Pay to PubKey (uncompressed) with duplicate merge
	//for _, hashType := range hashTypes {
	//	for _, suite := range signatureSuites {
	//		for i := range tx.TxIn {
	//			var keyDB []byte
	//
	//			msg := fmt.Sprintf("%d:%d:%d", hashType, i, suite)
	//			var address stdaddr.Address
	//			var err error
	//			switch suite {
	//			case dcrec.STEcdsaSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pk := privKey.PubKey()
	//				address, err = stdaddr.NewAddressPubKeyEcdsaSecp256k1V0(pk,
	//					testingParams)
	//
	//			case dcrec.STEd25519:
	//				keyDB, _, _, _ = edwards.GenerateKey(rand.Reader)
	//				_, pk := edwards.PrivKeyFromBytes(keyDB)
	//				pkBytes := pk.SerializeUncompressed()
	//				address, err = stdaddr.NewAddressPubKeyEd25519V0Raw(pkBytes,
	//					testingParams)
	//
	//			case dcrec.STSchnorrSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pk := privKey.PubKey()
	//				address, err = stdaddr.NewAddressPubKeySchnorrSecp256k1V0(pk,
	//					testingParams)
	//			}
	//			if err != nil {
	//				t.Errorf("failed to make address for %s: %v", msg, err)
	//				break
	//			}
	//
	//			_, pkScript := address.PaymentScript()
	//
	//			scriptAddr, err := stdaddr.NewAddressScriptHashV0(pkScript,
	//				testingParams)
	//			if err != nil {
	//				t.Errorf("failed to make p2sh addr for %s: %v", msg, err)
	//			}
	//
	//			_, scriptPkScript := scriptAddr.PaymentScript()
	//
	//			// Without treasury agenda.
	//			_, err = sign.SignTxOutput(testingParams,
	//				tx, i, scriptPkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(map[string][]byte{
	//					scriptAddr.String(): pkScript,
	//				}), nil, noTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s: %v", msg,
	//					err)
	//				break
	//			}
	//
	//			// by the above loop, this should be valid, now sign
	//			// again and merge.
	//			sigScript, err := sign.SignTxOutput(testingParams,
	//				tx, i, scriptPkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(map[string][]byte{
	//					scriptAddr.String(): pkScript,
	//				}), nil, noTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s a "+
	//					"second time: %v", msg, err)
	//				break
	//			}
	//
	//			err = checkScripts(msg, tx, i, sigScript, scriptPkScript)
	//			if err != nil {
	//				t.Errorf("twice signed script invalid for "+
	//					"%s: %v", msg, err)
	//				break
	//			}
	//
	//			// With treasury agenda.
	//			_, err = sign.SignTxOutput(testingParams,
	//				tx, i, scriptPkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(map[string][]byte{
	//					scriptAddr.String(): pkScript,
	//				}), nil, withTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s: %v", msg,
	//					err)
	//				break
	//			}
	//
	//			// by the above loop, this should be valid, now sign
	//			// again and merge.
	//			sigScript, err = sign.SignTxOutput(testingParams,
	//				tx, i, scriptPkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(map[string][]byte{
	//					scriptAddr.String(): pkScript,
	//				}), nil, withTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s a "+
	//					"second time: %v", msg, err)
	//				break
	//			}
	//
	//			err = checkScripts(msg, tx, i, sigScript, scriptPkScript)
	//			if err != nil {
	//				t.Errorf("twice signed script invalid for "+
	//					"%s: %v", msg, err)
	//				break
	//			}
	//		}
	//	}
	//}
	//
	//// Pay to PubKey (compressed)
	//for _, hashType := range hashTypes {
	//	for _, suite := range signatureSuites {
	//		for i := range tx.TxIn {
	//			var keyDB []byte
	//
	//			msg := fmt.Sprintf("%d:%d:%d", hashType, i, suite)
	//			var address stdaddr.Address
	//			var err error
	//			switch suite {
	//			case dcrec.STEcdsaSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pk := privKey.PubKey()
	//				address, err = stdaddr.NewAddressPubKeyEcdsaSecp256k1V0(pk,
	//					testingParams)
	//
	//			case dcrec.STEd25519:
	//				keyDB, _, _, _ = edwards.GenerateKey(rand.Reader)
	//				_, pk := edwards.PrivKeyFromBytes(keyDB)
	//				pkBytes := pk.SerializeCompressed()
	//				address, err = stdaddr.NewAddressPubKeyEd25519V0Raw(pkBytes,
	//					testingParams)
	//
	//			case dcrec.STSchnorrSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pk := privKey.PubKey()
	//				address, err = stdaddr.NewAddressPubKeySchnorrSecp256k1V0(pk,
	//					testingParams)
	//			}
	//			if err != nil {
	//				t.Errorf("failed to make address for %s: %v", msg, err)
	//				break
	//			}
	//
	//			_, pkScript := address.PaymentScript()
	//
	//			scriptAddr, err := stdaddr.NewAddressScriptHashV0(pkScript,
	//				testingParams)
	//			if err != nil {
	//				t.Errorf("failed to make p2sh addr for %s: %v", msg, err)
	//				break
	//			}
	//
	//			_, scriptPkScript := scriptAddr.PaymentScript()
	//
	//			// Without treasury agenda.
	//			if err := signAndCheck(msg, tx, i, scriptPkScript,
	//				hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(map[string][]byte{
	//					scriptAddr.String(): pkScript,
	//				}), noTreasury); err != nil {
	//				t.Error(err)
	//				break
	//			}
	//
	//			if err := signBadAndCheck(msg, tx, i, pkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(nil), noTreasury); err == nil {
	//				t.Errorf("corrupted signature validated: %s", msg)
	//				break
	//			}
	//
	//			// With treasury agenda.
	//			if err := signAndCheck(msg, tx, i, scriptPkScript,
	//				hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(map[string][]byte{
	//					scriptAddr.String(): pkScript,
	//				}), withTreasury); err != nil {
	//				t.Error(err)
	//				break
	//			}
	//
	//			if err := signBadAndCheck(msg, tx, i, pkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, false},
	//				}), mkGetScript(nil), withTreasury); err == nil {
	//				t.Errorf("corrupted signature validated: %s", msg)
	//				break
	//			}
	//		}
	//	}
	//}
	//
	//// Pay to PubKey (compressed)
	//for _, hashType := range hashTypes {
	//	for _, suite := range signatureSuites {
	//		for i := range tx.TxIn {
	//			var keyDB []byte
	//
	//			msg := fmt.Sprintf("%d:%d:%d", hashType, i, suite)
	//			var address stdaddr.Address
	//			var err error
	//			switch suite {
	//			case dcrec.STEcdsaSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pk := privKey.PubKey()
	//				address, err = stdaddr.NewAddressPubKeyEcdsaSecp256k1V0(pk,
	//					testingParams)
	//
	//			case dcrec.STEd25519:
	//				keyDB, _, _, _ = edwards.GenerateKey(rand.Reader)
	//				_, pk := edwards.PrivKeyFromBytes(keyDB)
	//				pkBytes := pk.SerializeCompressed()
	//				address, err = stdaddr.NewAddressPubKeyEd25519V0Raw(pkBytes,
	//					testingParams)
	//
	//			case dcrec.STSchnorrSecp256k1:
	//				privKey, _ := secp256k1.GeneratePrivateKey()
	//				keyDB = privKey.Serialize()
	//				pk := privKey.PubKey()
	//				address, err = stdaddr.NewAddressPubKeySchnorrSecp256k1V0(pk,
	//					testingParams)
	//			}
	//			if err != nil {
	//				t.Errorf("failed to make address for %s: %v", msg, err)
	//				break
	//			}
	//
	//			_, pkScript := address.PaymentScript()
	//
	//			scriptAddr, err := stdaddr.NewAddressScriptHashV0(pkScript,
	//				testingParams)
	//			if err != nil {
	//				t.Errorf("failed to make p2sh addr for %s: %v", msg, err)
	//				break
	//			}
	//
	//			_, scriptPkScript := scriptAddr.PaymentScript()
	//
	//			// Without treasury agenda.
	//			_, err = sign.SignTxOutput(testingParams,
	//				tx, i, scriptPkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(map[string][]byte{
	//					scriptAddr.String(): pkScript,
	//				}), nil, noTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s: %v", msg,
	//					err)
	//				break
	//			}
	//
	//			// by the above loop, this should be valid, now sign
	//			// again and merge.
	//			sigScript, err := sign.SignTxOutput(testingParams,
	//				tx, i, scriptPkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(map[string][]byte{
	//					scriptAddr.String(): pkScript,
	//				}), nil, noTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s a "+
	//					"second time: %v", msg, err)
	//				break
	//			}
	//
	//			err = checkScripts(msg, tx, i, sigScript, scriptPkScript)
	//			if err != nil {
	//				t.Errorf("twice signed script invalid for "+
	//					"%s: %v", msg, err)
	//				break
	//			}
	//
	//			// With treasury agenda.
	//			_, err = sign.SignTxOutput(testingParams,
	//				tx, i, scriptPkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(map[string][]byte{
	//					scriptAddr.String(): pkScript,
	//				}), nil, withTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s: %v", msg,
	//					err)
	//				break
	//			}
	//
	//			// by the above loop, this should be valid, now sign
	//			// again and merge.
	//			sigScript, err = sign.SignTxOutput(testingParams,
	//				tx, i, scriptPkScript, hashType,
	//				mkGetKey(map[string]addressToKey{
	//					address.String(): {keyDB, suite, true},
	//				}), mkGetScript(map[string][]byte{
	//					scriptAddr.String(): pkScript,
	//				}), nil, withTreasury)
	//			if err != nil {
	//				t.Errorf("failed to sign output %s a "+
	//					"second time: %v", msg, err)
	//				break
	//			}
	//
	//			err = checkScripts(msg, tx, i, sigScript, scriptPkScript)
	//			if err != nil {
	//				t.Errorf("twice signed script invalid for "+
	//					"%s: %v", msg, err)
	//				break
	//			}
	//		}
	//	}
	//}

	// Basic Multisig
	//for _, hashType := range hashTypes {
	//	for i := range tx.TxIn {
	//		msg := fmt.Sprintf("%d:%d", hashType, i)
	//
	//		privKey1, err := secp256k1.GeneratePrivateKey()
	//		if err != nil {
	//			t.Errorf("failed to generate key: %v", err)
	//			break
	//		}
	//		keyDB1 := privKey1.Serialize()
	//		pk1 := privKey1.PubKey()
	//
	//		address1, err := stdaddr.NewAddressPubKeyEcdsaSecp256k1V0(pk1,
	//			testingParams)
	//		if err != nil {
	//			t.Errorf("failed to make address for %s: %v", msg, err)
	//			break
	//		}
	//
	//		privKey2, err := secp256k1.GeneratePrivateKey()
	//		if err != nil {
	//			t.Errorf("failed to generate key: %v", err)
	//			break
	//		}
	//		keyDB2 := privKey2.Serialize()
	//		pk2 := privKey2.PubKey()
	//
	//		address2, err := stdaddr.NewAddressPubKeyEcdsaSecp256k1V0(pk2,
	//			testingParams)
	//		if err != nil {
	//			t.Errorf("failed to make address 2 for %s: %v", msg, err)
	//			break
	//		}
	//
	//		pkScript, err := stdscript.MultiSigScriptV0(2,
	//			pk1.SerializeCompressed(), pk2.SerializeCompressed())
	//		if err != nil {
	//			t.Errorf("failed to make pkscript for %s: %v", msg, err)
	//		}
	//
	//		scriptAddr, err := stdaddr.NewAddressScriptHashV0(pkScript,
	//			testingParams)
	//		if err != nil {
	//			t.Errorf("failed to make p2sh addr for %s: %v", msg, err)
	//			break
	//		}
	//
	//		_, scriptPkScript := scriptAddr.PaymentScript()
	//
	//		suite1 := dcrec.STEcdsaSecp256k1
	//		suite2 := dcrec.STEcdsaSecp256k1
	//
	//		// With treasury agenda.
	//		if err := signAndCheck(msg, tx, i, scriptPkScript,
	//			hashType,
	//			mkGetKey(map[string]addressToKey{
	//				address1.String(): {keyDB1, suite1, true},
	//				address2.String(): {keyDB2, suite2, true},
	//			}), mkGetScript(map[string][]byte{
	//				scriptAddr.String(): pkScript,
	//			}), withTreasury); err != nil {
	//			t.Error(err)
	//			break
	//		}
	//
	//		if err := signBadAndCheck(msg, tx, i, pkScript, hashType,
	//			mkGetKey(map[string]addressToKey{
	//				address1.String(): {keyDB1, suite1, true},
	//				address2.String(): {keyDB2, suite2, true},
	//			}), mkGetScript(nil), withTreasury); err == nil {
	//			t.Errorf("corrupted signature validated: %s", msg)
	//			break
	//		}
	//	}
	//}

	// Two part multisig, sign with one key then the other.
	for _, hashType := range hashTypes {
		for i := range tx.TxIn {
			msg := fmt.Sprintf("%d:%d", hashType, i)

			privKey1, err := secp256k1.GeneratePrivateKey()
			if err != nil {
				t.Errorf("failed to generate key: %v", err)
				break
			}
			keyDB1 := privKey1.Serialize()
			pk1 := privKey1.PubKey()

			address1, err := stdaddr.NewAddressPubKeyEcdsaSecp256k1V0(pk1,
				testingParams)
			if err != nil {
				t.Errorf("failed to make address for %s: %v", msg, err)
				break
			}

			privKey2, err := secp256k1.GeneratePrivateKey()
			if err != nil {
				t.Errorf("failed to generate key: %v", err)
				break
			}
			keyDB2 := privKey2.Serialize()
			pk2 := privKey2.PubKey()

			address2, err := stdaddr.NewAddressPubKeyEcdsaSecp256k1V0(pk2,
				testingParams)
			if err != nil {
				t.Errorf("failed to make address 2 for %s: %v", msg, err)
				break
			}

			pkScript, err := stdscript.MultiSigScriptV0(2,
				pk1.SerializeCompressed(), pk2.SerializeCompressed())
			if err != nil {
				t.Errorf("failed to make pkscript "+
					"for %s: %v", msg, err)
			}

			scriptAddr, err := stdaddr.NewAddressScriptHashV0(pkScript,
				testingParams)
			if err != nil {
				t.Errorf("failed to make p2sh addr for %s: %v", msg, err)
				break
			}

			_, scriptPkScript := scriptAddr.PaymentScript()

			prevOutDisasm, err := txscript.DisasmString(scriptPkScript)
			if err != nil {
				panic(err)
			}
			fmt.Println(fmt.Sprintf("PREV_OUT: %s", prevOutDisasm))

			// Without treasury agenda.
			suite1 := dcrec.STEcdsaSecp256k1
			suite2 := dcrec.STEcdsaSecp256k1

			// With treasury agenda.
			sigScript, err := sign.SignTxOutput(testingParams, tx, i,
				scriptPkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address1.String(): {keyDB1, suite1, true},
				}), mkGetScript(map[string][]byte{
					scriptAddr.String(): pkScript,
				}), nil, withTreasury)
			if err != nil {
				t.Errorf("failed to sign output %s: %v", msg,
					err)
				break
			}

			sigScriptDisasmBefore, err := txscript.DisasmString(sigScript)
			if err != nil {
				panic(err)
			}
			fmt.Println(fmt.Sprintf("sigScriptDisasmBefore: %s", sigScriptDisasmBefore))
			vm, err := txscript.NewEngine(sigScript, tx, i,
				sanityVerifyFlags, scriptVersionAssumed, nil)
			if err != nil {
				panic(err)
			}
			fmt.Println()
			fmt.Println("BEFORE ============================================================")
			disasm, err := vm.DisasmScript(0)
			if err != nil {
				panic(err)
			}
			fmt.Println(fmt.Sprintf("%s", disasm))
			disasm, err = vm.DisasmScript(1)
			if err != nil {
				panic(err)
			}
			//fmt.Println(fmt.Sprintf("%s", disasm))
			//disasm, err = vm.DisasmScript(2)
			//if err != nil {
			//	panic(err)
			//}
			fmt.Println(fmt.Sprintf("%s", disasm))
			fmt.Println()
			fmt.Println("BEFORE ============================================================")

			// Only 1 out of 2 signed, this *should* fail.
			if checkScripts(msg, tx, i, sigScript,
				scriptPkScript) == nil {
				t.Errorf("part signed script valid for %s", msg)
				break
			}

			// Sign with the other key and merge
			sigScript, err = sign.SignTxOutput(testingParams, tx, i,
				scriptPkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address2.String(): {keyDB2, suite2, true},
				}), mkGetScript(map[string][]byte{
					scriptAddr.String(): pkScript,
				}), sigScript, withTreasury)
			if err != nil {
				t.Errorf("failed to sign output %s: %v", msg, err)
				break
			}

			redeemDisasm, err := txscript.DisasmString(pkScript)
			if err != nil {
				panic(err)
			}
			fmt.Println(fmt.Sprintf("REDEEM (hex): %x", pkScript))
			fmt.Println(fmt.Sprintf("REDEEM: %s", redeemDisasm))
			sigScriptDisasmAfter, err := txscript.DisasmString(sigScript)
			if err != nil {
				panic(err)
			}
			fmt.Println(fmt.Sprintf("sigScriptDisasmAfter: %s", sigScriptDisasmAfter))

			vm, err = txscript.NewEngine(sigScript, tx, i,
				sanityVerifyFlags, scriptVersionAssumed, nil)
			if err != nil {
				panic(err)
			}
			fmt.Println()
			fmt.Println("AFTER ============================================================")
			disasm, err = vm.DisasmScript(0)
			if err != nil {
				panic(err)
			}
			fmt.Println(fmt.Sprintf("%s", disasm))
			disasm, err = vm.DisasmScript(1)
			if err != nil {
				panic(err)
			}
			//fmt.Println(fmt.Sprintf("%s", disasm))
			//disasm, err = vm.DisasmScript(2)
			//if err != nil {
			//	panic(err)
			//}
			fmt.Println(fmt.Sprintf("%s", disasm))
			fmt.Println()
			fmt.Println("AFTER ============================================================")

			err = checkScripts(msg, tx, i, sigScript,
				scriptPkScript)
			if err != nil {
				t.Errorf("fully signed script invalid for "+
					"%s: %v", msg, err)
				break
			}
		}
	}

	// Two part multisig, sign with one key then both, check key dedup
	// correctly.
	for _, hashType := range hashTypes {
		for i := range tx.TxIn {
			msg := fmt.Sprintf("%d:%d", hashType, i)

			privKey1, err := secp256k1.GeneratePrivateKey()
			if err != nil {
				t.Errorf("failed to generate key: %v", err)
				break
			}
			keyDB1 := privKey1.Serialize()
			pk1 := privKey1.PubKey()

			address1, err := stdaddr.NewAddressPubKeyEcdsaSecp256k1V0(pk1,
				testingParams)
			if err != nil {
				t.Errorf("failed to make address for %s: %v", msg, err)
				break
			}

			privKey2, err := secp256k1.GeneratePrivateKey()
			if err != nil {
				t.Errorf("failed to generate key: %v", err)
				break
			}
			keyDB2 := privKey2.Serialize()
			pk2 := privKey2.PubKey()
			address2, err := stdaddr.NewAddressPubKeyEcdsaSecp256k1V0(pk2,
				testingParams)
			if err != nil {
				t.Errorf("failed to make address 2 for %s: %v", msg, err)
				break
			}

			pkScript, err := stdscript.MultiSigScriptV0(2,
				pk1.SerializeCompressed(), pk2.SerializeCompressed())
			if err != nil {
				t.Errorf("failed to make pkscript for %s: %v", msg, err)
			}

			scriptAddr, err := stdaddr.NewAddressScriptHashV0(pkScript,
				testingParams)
			if err != nil {
				t.Errorf("failed to make p2sh addr for %s: %v", msg, err)
				break
			}

			_, scriptPkScript := scriptAddr.PaymentScript()
			if err != nil {
				t.Errorf("failed to make script pkscript for %s: %v", msg, err)
				break
			}

			// Without treasury agenda.
			suite1 := dcrec.STEcdsaSecp256k1
			suite2 := dcrec.STEcdsaSecp256k1
			sigScript, err := sign.SignTxOutput(testingParams, tx, i,
				scriptPkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address1.String(): {keyDB1, suite1, true},
				}), mkGetScript(map[string][]byte{
					scriptAddr.String(): pkScript,
				}), nil, noTreasury)
			if err != nil {
				t.Errorf("failed to sign output %s: %v", msg,
					err)
				break
			}

			// Only 1 out of 2 signed, this *should* fail.
			if checkScripts(msg, tx, i, sigScript,
				scriptPkScript) == nil {
				t.Errorf("part signed script valid for %s", msg)
				break
			}

			// Sign with the other key and merge
			sigScript, err = sign.SignTxOutput(testingParams, tx, i,
				scriptPkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address1.String(): {keyDB1, suite1, true},
					address2.String(): {keyDB2, suite2, true},
				}), mkGetScript(map[string][]byte{
					scriptAddr.String(): pkScript,
				}), sigScript, noTreasury)
			if err != nil {
				t.Errorf("failed to sign output %s: %v", msg, err)
				break
			}

			// Now we should pass.
			err = checkScripts(msg, tx, i, sigScript,
				scriptPkScript)
			if err != nil {
				t.Errorf("fully signed script invalid for "+
					"%s: %v", msg, err)
				break
			}

			// With treasury agenda.
			sigScript, err = sign.SignTxOutput(testingParams, tx, i,
				scriptPkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address1.String(): {keyDB1, suite1, true},
				}), mkGetScript(map[string][]byte{
					scriptAddr.String(): pkScript,
				}), nil, withTreasury)
			if err != nil {
				t.Errorf("failed to sign output %s: %v", msg,
					err)
				break
			}

			// Only 1 out of 2 signed, this *should* fail.
			if checkScripts(msg, tx, i, sigScript,
				scriptPkScript) == nil {
				t.Errorf("part signed script valid for %s", msg)
				break
			}

			// Sign with the other key and merge
			sigScript, err = sign.SignTxOutput(testingParams, tx, i,
				scriptPkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address1.String(): {keyDB1, suite1, true},
					address2.String(): {keyDB2, suite2, true},
				}), mkGetScript(map[string][]byte{
					scriptAddr.String(): pkScript,
				}), sigScript, withTreasury)
			if err != nil {
				t.Errorf("failed to sign output %s: %v", msg, err)
				break
			}

			// Now we should pass.
			err = checkScripts(msg, tx, i, sigScript,
				scriptPkScript)
			if err != nil {
				t.Errorf("fully signed script invalid for "+
					"%s: %v", msg, err)
				break
			}
		}
	}
}

type tstInput struct {
	txout              *wire.TxOut
	sigscriptGenerates bool
	inputValidates     bool
	indexOutOfRange    bool
}

type tstSigScript struct {
	name               string
	inputs             []tstInput
	hashType           txscript.SigHashType
	compress           bool
	scriptAtWrongIndex bool
}

func mkGetScript(scripts map[string][]byte) sign.ScriptDB {
	if scripts == nil {
		return sign.ScriptClosure(func(addr stdaddr.Address) (
			[]byte, error) {
			return nil, errors.New("nope 3")
		})
	}
	return sign.ScriptClosure(func(addr stdaddr.Address) ([]byte,
		error) {
		script, ok := scripts[addr.String()]
		if !ok {
			return nil, errors.New("nope 4")
		}
		return script, nil
	})
}

type addressToKey struct {
	key        []byte
	sigType    dcrec.SignatureType
	compressed bool
}

func mkGetKey(keys map[string]addressToKey) sign.KeyDB {
	if keys == nil {
		return sign.KeyClosure(func(addr stdaddr.Address) ([]byte,
			dcrec.SignatureType, bool, error) {
			return nil, 0, false, errors.New("nope 1")
		})
	}
	return sign.KeyClosure(func(addr stdaddr.Address) ([]byte,
		dcrec.SignatureType, bool, error) {
		a2k, ok := keys[addr.String()]
		if !ok {
			return nil, 0, false, errors.New("nope 2")
		}
		//panic("getting key")
		return a2k.key, a2k.sigType, a2k.compressed, nil
	})
}

func mkGetKeyPub(keys map[string]addressToKey) sign.KeyDB {
	if keys == nil {
		return sign.KeyClosure(func(addr stdaddr.Address) ([]byte,
			dcrec.SignatureType, bool, error) {
			return nil, 0, false, errors.New("nope 1")
		})
	}
	return sign.KeyClosure(func(addr stdaddr.Address) ([]byte,
		dcrec.SignatureType, bool, error) {
		a2k, ok := keys[addr.String()]
		if !ok {
			return nil, 0, false, errors.New("nope 2")
		}
		return a2k.key, a2k.sigType, a2k.compressed, nil
	})
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

func signAndCheck(msg string, tx *wire.MsgTx, idx int, pkScript []byte,
	hashType txscript.SigHashType, kdb sign.KeyDB, sdb sign.ScriptDB,
	isTreasuryEnabled bool) error {

	sigScript, err := sign.SignTxOutput(testingParams, tx, idx, pkScript,
		hashType, kdb, sdb, nil, isTreasuryEnabled)
	if err != nil {
		return fmt.Errorf("failed to sign output %s: %v", msg, err)
	}

	return checkScripts(msg, tx, idx, sigScript, pkScript)
}

func signBadAndCheck(msg string, tx *wire.MsgTx, idx int, pkScript []byte,
	hashType txscript.SigHashType, kdb sign.KeyDB, sdb sign.ScriptDB,
	isTreasuryEnabled bool) error {

	// Setup a PRNG.
	randScriptHash := chainhash.HashB(pkScript)
	tRand := mrand.New(mrand.NewSource(int64(randScriptHash[0])))

	sigScript, err := sign.SignTxOutput(testingParams, tx,
		idx, pkScript, hashType, kdb, sdb, nil, isTreasuryEnabled)
	if err != nil {
		return fmt.Errorf("failed to sign output %s: %v", msg, err)
	}

	// Be sure to reset the value in when we're done creating the
	// corrupted signature for that flag.
	tx.TxIn[0].ValueIn = testValueIn

	// Corrupt a random bit in the signature.
	pos := tRand.Intn(len(sigScript) - 1)
	bitPos := tRand.Intn(7)
	sigScript[pos] ^= 1 << uint8(bitPos)

	return checkScripts(msg, tx, idx, sigScript, pkScript)
}

// testingParams defines the chain params to use throughout these tests so it
// can more easily be changed if desired.
var testingParams = chaincfg.RegNetParams()

const (
	testValueIn = 12345

	// noTreasury signifies the treasury agenda should be treated as though
	// it is inactive.  It is used to increase the readability of the
	// tests.
	noTreasury = false

	// withTreasury signifies the treasury agenda should be treated as
	// though it is active.  It is used to increase the readability of
	// the tests.
	withTreasury = true
)

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
