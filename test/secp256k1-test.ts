'use strict'
import BN = require('bn.js')
import 'mocha'

import {MasterKeyPair, MasterKeyShare, Mnemonics, Purpose, SigAlg, extendedPubSharesAgg, mnemonicToExtendedPub} from ".."
import * as bip39 from "bip39";

function printParty(index: number, mnemo: Mnemonics, masterKeyShare: MasterKeyShare): void{
    console.log("\n- party ", index, ": ")
    console.log("mnemo: ", mnemo.mnemo)
    console.log("extraMnemo: ", mnemo.extraMnemo)
    console.log("ks: ", masterKeyShare.keyShare.toString(16))
    console.log("cs: ", masterKeyShare.chainCodeShare.toString(16))
}

describe('For fresh users', function () {
    it('Random Mnemonic!', function () {
        let mnemo1 = Mnemonics.generateMnemonic()
        let masterKeyShare1 = mnemo1.derive(Purpose.MASTER_KEY_DERIVE, SigAlg.ECDSA_SECP256K1, 0)
        printParty(1, mnemo1, masterKeyShare1)

        let mnemo2 = Mnemonics.generateMnemonic()
        let masterKeyShare2 = mnemo2.derive(Purpose.MASTER_KEY_DERIVE, SigAlg.ECDSA_SECP256K1, 0)
        printParty(2, mnemo2, masterKeyShare2)

        let mnemo3 = Mnemonics.generateMnemonic()
        let masterKeyShare3 = mnemo3.derive(Purpose.MASTER_KEY_DERIVE, SigAlg.ECDSA_SECP256K1, 0)
        printParty(3, mnemo3, masterKeyShare3)

        let masterKeyPair = MasterKeyPair.recoverFromMasterKeyShares([masterKeyShare1, masterKeyShare2, masterKeyShare3], SigAlg.ECDSA_SECP256K1)
        console.log("\n", masterKeyPair)

        let expected_masterKeyPair = MasterKeyPair.recoverFromMnemonics([mnemo1, mnemo2, mnemo3], SigAlg.ECDSA_SECP256K1)
        console.log("\n", expected_masterKeyPair)
        console.assert(masterKeyPair.xpub === expected_masterKeyPair.xpub)
        console.assert(masterKeyPair.xprv === expected_masterKeyPair.xprv)
    })

    it('Deterministic Mnemonic ', function () {
        let mnemo1 = new Mnemonics("turtle stone jacket logic canal thing project hub dash issue remove same beauty hospital finish brush pear hire follow dinner industry release general flock", "")
        let masterKeyShare1 = mnemo1.derive(Purpose.MASTER_KEY_DERIVE, SigAlg.ECDSA_SECP256K1, 0)
        printParty(1, mnemo1, masterKeyShare1)

        let mnemo2 = new Mnemonics("swim such enlist acoustic warm enrich weekend milk asthma pistol equip man whip hammer sponsor essence test token pudding ethics cliff light fine outdoor", "")
        let masterKeyShare2 = mnemo2.derive(Purpose.MASTER_KEY_DERIVE, SigAlg.ECDSA_SECP256K1, 0)
        printParty(2, mnemo2, masterKeyShare2)

        let mnemo3 = new Mnemonics("heavy suffer taste bag dawn furnace feed stuff shaft rally armor ginger urban anxiety split country antenna erase burst grass cricket cream broom sail", "")
        let masterKeyShare3 = mnemo3.derive(Purpose.MASTER_KEY_DERIVE, SigAlg.ECDSA_SECP256K1, 0)
        printParty(3, mnemo3, masterKeyShare3)

        let masterKeyPair = MasterKeyPair.recoverFromMasterKeyShares([masterKeyShare1, masterKeyShare2, masterKeyShare3], SigAlg.ECDSA_SECP256K1)
        console.log("\n", masterKeyPair)

        let expected_masterKeyPair = MasterKeyPair.recoverFromMnemonics([mnemo1, mnemo2, mnemo3], SigAlg.ECDSA_SECP256K1)
        console.log("\n", expected_masterKeyPair)
        console.assert(masterKeyPair.xpub === expected_masterKeyPair.xpub)
        console.assert(masterKeyPair.xprv === expected_masterKeyPair.xprv)
    })
})

describe('For old users', function () {
    it('From Sign Key on Secp256k1!', function () {
        let chainCode1 = new BN("5555555555555555555555555555555555555555555555555555555555555555")
        let keyShare1 = new BN("1111111111111111111111111111111111111111111111111111111111111111")
        let masterKeyShare1 = new MasterKeyShare(keyShare1, chainCode1, true)

        let chainCode2 = new BN("5555555555555555555555555555555555555555555555555555555555555555")
        let keyShare2 = new BN("2222222222222222222222222222222222222222222222222222222222222222")
        let masterKeyShare2 = new MasterKeyShare(keyShare2, chainCode2, true)

        let chainCode3 = new BN("5555555555555555555555555555555555555555555555555555555555555555")
        let keyShare3 = new BN("3333333333333333333333333333333333333333333333333333333333333333")
        let masterKeyShare3 = new MasterKeyShare(keyShare3, chainCode3, true)

        let masterKeyPair = MasterKeyPair.recoverFromMasterKeyShares([masterKeyShare1, masterKeyShare2, masterKeyShare3], SigAlg.ECDSA_SECP256K1)
        console.log("\n", masterKeyPair)

        let mnemo1 = Mnemonics.createMnemonics(keyShare1, chainCode1)
        printParty(1, mnemo1, masterKeyShare1)
        let mnemo2 = Mnemonics.createMnemonics(keyShare2, chainCode2)
        printParty(2, mnemo2, masterKeyShare2)
        let mnemo3 = Mnemonics.createMnemonics(keyShare3, chainCode3)
        printParty(3, mnemo3, masterKeyShare3)
        let expected_masterKeyPair = MasterKeyPair.recoverFromMnemonics([mnemo1, mnemo2, mnemo3], SigAlg.ECDSA_SECP256K1)
        console.log("\n", expected_masterKeyPair)
        console.assert(masterKeyPair.xpub === expected_masterKeyPair.xpub)
        console.assert(masterKeyPair.xprv === expected_masterKeyPair.xprv)
    })
})

describe('test mnemonicToExtendedPub function and extendedPubSharesAgg function', function () {
    it('new user.', function () {
        for (let i = 0; i < 100; ++i) {
            let mnemo1 = Mnemonics.generateMnemonic()
            let mnemo2 = Mnemonics.generateMnemonic()
            let mnemo3 = Mnemonics.generateMnemonic()
            let expected_masterKeyPair = MasterKeyPair.recoverFromMnemonics([mnemo1, mnemo2, mnemo3], SigAlg.ECDSA_SECP256K1)

            let extendedpub1 = mnemonicToExtendedPub(SigAlg.ECDSA_SECP256K1, 0, mnemo1.mnemo)
            let extendedpub2 = mnemonicToExtendedPub(SigAlg.ECDSA_SECP256K1, 0, mnemo2.mnemo)
            let extendedpub3 = mnemonicToExtendedPub(SigAlg.ECDSA_SECP256K1, 0, mnemo3.mnemo)
            let extendedPubShares = [extendedpub1, extendedpub2, extendedpub3]
            let masterExtendedPub = extendedPubSharesAgg(SigAlg.ECDSA_SECP256K1, extendedPubShares, false)
            console.assert(expected_masterKeyPair.xpub === masterExtendedPub)
        }
    })
    it("old user.", function(){
        for (let i = 0; i < 100; ++i) {
            let extraMnemo = bip39.generateMnemonic(256)
            let mnemo1 = bip39.generateMnemonic(256)
            let mnemo2 = bip39.generateMnemonic(256)
            let mnemo3 = bip39.generateMnemonic(256)
            let mnemoObj1 = new Mnemonics(mnemo1, extraMnemo)
            let mnemoObj2 = new Mnemonics(mnemo2, extraMnemo)
            let mnemoObj3 = new Mnemonics(mnemo3, extraMnemo)
            let expected_masterKeyPair = MasterKeyPair.recoverFromMnemonics([mnemoObj1, mnemoObj2, mnemoObj3], SigAlg.ECDSA_SECP256K1)

            let chaincode = bip39.mnemonicToEntropy(extraMnemo)
            let extendedpub1 = mnemonicToExtendedPub(SigAlg.ECDSA_SECP256K1, 0, mnemo1, chaincode)
            let extendedpub2 = mnemonicToExtendedPub(SigAlg.ECDSA_SECP256K1, 0, mnemo2, chaincode)
            let extendedpub3 = mnemonicToExtendedPub(SigAlg.ECDSA_SECP256K1, 0, mnemo3, chaincode)
            let extendedPubShares = [extendedpub1, extendedpub2, extendedpub3]
            let masterExtendedPub = extendedPubSharesAgg(SigAlg.ECDSA_SECP256K1, extendedPubShares, true)
            console.assert(expected_masterKeyPair.xpub === masterExtendedPub)
        }
    })
})



