package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"

	"decred.org/dcrwallet/v4/wallet/udb"
	"github.com/decred/dcrd/dcrec"
	"github.com/decred/dcrd/txscript/v4"
	"github.com/decred/dcrd/txscript/v4/stdaddr"
	"github.com/decred/dcrd/txscript/v4/stdscript"
	"github.com/norwnd/multisig"
	"github.com/norwnd/multisig/signer"
)

var ctx = context.Background()

func _main() error {
	pubKey1Hex, _ := multisig.DeriveAddr(multisig.PubKey1MasterBase58)
	pubKey1Bytes, err := hex.DecodeString(pubKey1Hex)
	if err != nil {
		return err
	}
	//seedHex, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	//if err != nil {
	//	return err
	//}
	//fmt.Println(fmt.Sprintf("%x", seedHex))
	const seedHex = "eba815a7bb6fd72afc544895fe17647a0219e1bae56b82f8a038c52f71345918"
	seedBytes, err := hex.DecodeString(seedHex)
	if err != nil {
		return err
	}
	_, _, _, privKey2Master, err := udb.HDKeysFromSeed(seedBytes, multisig.ChainCfg)
	if err != nil {
		return err
	}
	privKey2MasterBytes, err := privKey2Master.SerializedPrivKey()
	if err != nil {
		return err
	}
	pubKey2Master := privKey2Master.Neuter()
	addr2, err := stdaddr.NewAddressPubKeyEcdsaSecp256k1V0Raw(
		pubKey2Master.SerializedPubKey(),
		multisig.ChainCfg,
	)
	if err != nil {
		return err
	}
	// Set up our callbacks that we pass to txscript, so it can
	// look up the appropriate keys and scripts by address.
	var db sigDataSource
	db.key = func(addr stdaddr.Address) ([]byte, dcrec.SignatureType, bool, error) {
		if addr.String() == addr2.String() {
			fmt.Println("GetKey: success")
			//panic("GetKey: success")
			// Is privKey2MasterBytes compressed or not ? It isn't clear but also
			// seems to not matter ... maybe check it later.
			//return privKey2MasterBytes, dcrec.STEcdsaSecp256k1, false, nil
			return privKey2MasterBytes, dcrec.STEcdsaSecp256k1, true, nil
		}
		fmt.Println("GetKey: failure")
		//panic("GetKey: failure")
		return nil, 0, false, fmt.Errorf("we don't own address: %s to sign it", addr.String())
	}
	// Since tx itself doesn't contain the pub keys for the input we are about to sign
	// we need to get these pub keys from somewhere; it's easy because we already have
	// it since currently we are re-using same address between different transactions
	// and pub key is kinda hardcoded, if we are to start deriving different addresses
	// from this pub key we'll need to derive the pub key required here too!
	redeemScript, err := stdscript.MultiSigScriptV0(2, pubKey1Bytes, pubKey2Master.SerializedPubKey())
	if err != nil {
		fmt.Println("GetScript: failure")
		//panic("GetScript: failure")
		return fmt.Errorf("stdscript.MultiSigScriptV0: %w", err)
	}
	db.script = func(addr stdaddr.Address) ([]byte, error) {
		if addr.String() == multisig.ExpMultisigAddr {
			fmt.Println("GetScript: success")
			//panic("GetScript: success")
			disasmScriptRedeem, err := txscript.DisasmString(redeemScript)
			if err != nil {
				panic(err)
			}
			fmt.Println(fmt.Sprintf("REDEEM: %s", disasmScriptRedeem))
			return redeemScript, nil // always just unsigned template redeem script
		}
		return nil, fmt.Errorf("we don't own address: %s to store any scripts for it", addr.String())
	}
	signedTx, err := signer.SignRawTransaction(
		ctx,
		multisig.PartiallySignedTx,
		db,
		db,
	)
	if err != nil {
		return err
	}

	// A snippet from dcrwallet that shows how keys are craeted/managed/encrypted
	//_, coinTypeSLIP0044KeyPriv, _, acctKeySLIP0044Priv, err := udb.HDKeysFromSeed(seedHex, multisig.ChainCfg)
	//if err != nil {
	//	return err
	//}
	//// The address manager needs the public extended key for the account.
	//acctKeySLIP0044Pub := acctKeySLIP0044Priv.Neuter()
	//
	//// Generate new master keys.  These master keys are used to protect the
	//// crypto keys that will be generated next.
	//scryptOpts := scryptOptionsForNet(chainParams.Net)
	//masterKeyPub, err := newSecretKey(&pubPassphrase, scryptOpts)
	//if err != nil {
	//	return err
	//}
	//masterKeyPriv, err := newSecretKey(&privPassphrase, scryptOpts)
	//if err != nil {
	//	return err
	//}
	//defer masterKeyPriv.Zero()
	//
	//// Generate new crypto public and private keys.  These keys are used to
	//// protect the actual public and private data such as addresses, and
	//// extended keys.
	//cryptoKeyPub, err := newCryptoKey()
	//if err != nil {
	//	return err
	//}
	//cryptoKeyPriv, err := newCryptoKey()
	//if err != nil {
	//	return err
	//}
	//defer cryptoKeyPriv.Zero()
	//
	//// Encrypt the crypto keys with the associated master keys.
	//cryptoKeyPubEnc, err := masterKeyPub.Encrypt(cryptoKeyPub.Bytes())
	//if err != nil {
	//	return errors.E(errors.Crypto, errors.Errorf("encrypt crypto pubkey: %v", err))
	//}
	//cryptoKeyPrivEnc, err := masterKeyPriv.Encrypt(cryptoKeyPriv.Bytes())
	//if err != nil {
	//	return errors.E(errors.Crypto, errors.Errorf("encrypt crypto privkey: %v", err))
	//}
	//
	//// Encrypt the SLIP0044 cointype keys with the associated crypto keys.
	//coinTypeSLIP0044KeyPub := coinTypeSLIP0044KeyPriv.Neuter()
	//ctpes = coinTypeSLIP0044KeyPub.String()
	//coinTypeSLIP0044PubEnc, err := cryptoKeyPub.Encrypt([]byte(ctpes))
	//if err != nil {
	//	return errors.E(errors.Crypto, fmt.Errorf("encrypt SLIP0044 cointype pubkey: %v", err))
	//}
	//ctpes = coinTypeSLIP0044KeyPriv.String()
	//coinTypeSLIP0044PrivEnc, err := cryptoKeyPriv.Encrypt([]byte(ctpes))
	//if err != nil {
	//	return errors.E(errors.Crypto, fmt.Errorf("encrypt SLIP0044 cointype privkey: %v", err))
	//}
	//
	//// Encrypt the default account keys with the associated crypto keys.
	//apes := acctKeyLegacyPub.String()
	//acctPubLegacyEnc, err := cryptoKeyPub.Encrypt([]byte(apes))
	//if err != nil {
	//	return errors.E(errors.Crypto, fmt.Errorf("encrypt account 0 pubkey: %v", err))
	//}
	//apes = acctKeyLegacyPriv.String()
	//acctPrivLegacyEnc, err := cryptoKeyPriv.Encrypt([]byte(apes))
	//if err != nil {
	//	return errors.E(errors.Crypto, fmt.Errorf("encrypt account 0 privkey: %v", err))
	//}
	//apes = acctKeySLIP0044Pub.String()
	//acctPubSLIP0044Enc, err := cryptoKeyPub.Encrypt([]byte(apes))
	//if err != nil {
	//	return errors.E(errors.Crypto, fmt.Errorf("encrypt account 0 pubkey: %v", err))
	//}
	//apes = acctKeySLIP0044Priv.String()
	//acctPrivSLIP0044Enc, err := cryptoKeyPriv.Encrypt([]byte(apes))
	//if err != nil {
	//	return errors.E(errors.Crypto, fmt.Errorf("encrypt account 0 privkey: %v", err))
	//}
	//
	//// Save the master key params to the database.
	//pubParams := masterKeyPub.Marshal()
	//privParams := masterKeyPriv.Marshal()
	//err = putMasterKeyParams(ns, pubParams, privParams)
	//if err != nil {
	//	return err
	//}
	//
	//// Save the encrypted crypto keys to the database.
	//err = putCryptoKeys(ns, cryptoKeyPubEnc, cryptoKeyPrivEnc)
	//if err != nil {
	//	return err
	//}
	//
	//// Save the encrypted SLIP0044 cointype keys.
	//err = putCoinTypeSLIP0044Keys(ns, coinTypeSLIP0044PubEnc, coinTypeSLIP0044PrivEnc)
	//if err != nil {
	//	return err
	//}

	//fmt.Println(fmt.Sprintf("master pub (base58) 2: %s", pubKey2Master.String()))
	//fmt.Println(fmt.Sprintf("master pub 2: %s", hex.EncodeToString(pubKey2Master.SerializedPubKey())))
	//fmt.Println(fmt.Sprintf("addr 2: %s", addr2.String()))
	fmt.Println(fmt.Sprintf("signed tx: %s", signedTx))

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

type sigDataSource struct {
	key    func(stdaddr.Address) ([]byte, dcrec.SignatureType, bool, error)
	script func(stdaddr.Address) ([]byte, error)
}

func (s sigDataSource) GetKey(a stdaddr.Address) ([]byte, dcrec.SignatureType, bool, error) {
	return s.key(a)
}

func (s sigDataSource) GetScript(a stdaddr.Address) ([]byte, error) {
	return s.script(a)
}
