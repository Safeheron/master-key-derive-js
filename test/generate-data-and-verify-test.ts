'use strict'
import BN = require('bn.js')
import {MasterKeyPair, MasterKeyShare, Mnemonics, Purpose, SigAlg} from ".."
import 'mocha'
import * as fs from 'fs';

describe.skip('generate data and verify', function () {
    it('generate data', async function () {
        this.timeout(0)
        try {
            fs.writeFileSync('master_key_derivation_test_js.txt', '', "utf8")
        } catch(err) {
            return console.error(err)
        }
        for (let i = 0; i < 500000; i++) {
            let mnemo1 = Mnemonics.generateMnemonic()
            let mnemo2 = Mnemonics.generateMnemonic()
            let mnemo3 = Mnemonics.generateMnemonic()
            let ecdsa_masterKeyPair = MasterKeyPair.recoverFromMnemonics([mnemo1, mnemo2, mnemo3], SigAlg.ECDSA_SECP256K1)
            let eddsa_masterKeyPair = MasterKeyPair.recoverFromMnemonics([mnemo1, mnemo2, mnemo3], SigAlg.EDDSA_ED25519)

            try {
                fs.appendFileSync('master_key_derivation_test_js.txt', mnemo1.mnemo + '\n', "utf8")
                fs.appendFileSync('master_key_derivation_test_js.txt', mnemo2.mnemo + '\n', "utf8")
                fs.appendFileSync('master_key_derivation_test_js.txt', mnemo3.mnemo + '\n', "utf8")
                fs.appendFileSync('master_key_derivation_test_js.txt', ecdsa_masterKeyPair.xprv + '\n', "utf8")
                fs.appendFileSync('master_key_derivation_test_js.txt', ecdsa_masterKeyPair.xpub + '\n', "utf8")
                fs.appendFileSync('master_key_derivation_test_js.txt', eddsa_masterKeyPair.xprv + '\n', "utf8")
                fs.appendFileSync('master_key_derivation_test_js.txt', eddsa_masterKeyPair.xpub + '\n', "utf8")
            } catch (err) {
                return console.error(err)
            }
        }
    });

    it('consistency verification', async function (){
        this.timeout(0)
        let data
        try {
            data = fs.readFileSync("master_key_derivation_test_js.txt", "utf8")
        } catch (err) {
            return console.log(err)
        }
        const lines = data.split(/\r?\n/)

        for (let i = 0; i < lines.length; i = i + 7) {
            let mnemo1 = new Mnemonics(lines[i], "");
            let mnemo2 = new Mnemonics(lines[i + 1], "");
            let mnemo3 = new Mnemonics(lines[i + 2], "");

            let ecdsa_masterKeyPair = MasterKeyPair.recoverFromMnemonics([mnemo1, mnemo2, mnemo3], SigAlg.ECDSA_SECP256K1)
            let eddsa_masterKeyPair = MasterKeyPair.recoverFromMnemonics([mnemo1, mnemo2, mnemo3], SigAlg.EDDSA_ED25519)
            let expected_ecdsa_xprv = lines[i + 3]
            let expected_ecdsa_xpub = lines[i + 4]
            let expected_eddsa_xprv = lines[i + 5]
            let expected_eddsa_xpub = lines[i + 6]
            console.assert(ecdsa_masterKeyPair.xprv == expected_ecdsa_xprv)
            console.assert(ecdsa_masterKeyPair.xpub == expected_ecdsa_xpub)
            console.assert(eddsa_masterKeyPair.xprv == expected_eddsa_xprv)
            console.assert(eddsa_masterKeyPair.xpub == expected_eddsa_xpub)
        }
    })
})