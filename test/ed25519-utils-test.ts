'use strict'
import BN = require('bn.js')
import {Ed25519HDKey} from "@safeheron/crypto-bip32";
import 'mocha'

import {
    Mnemonics, MasterKeyShare, MasterKeyPair, Purpose, SigAlg, mnemonicToExtendedPub, extendedPubSharesAgg,
    ed25519_get_pubkey_hex,
    ed25519_sign,
    ed25519_verify,
    ed25519_hd_sign,
    ed25519_hd_verify
} from ".."

describe('ed25519 utils test 1', function () {
    it('simple sign test!', async function () {
        // hex: parsed in little endian
        let priv = "8765432187654321876543218765432187654321876543218765432187654321"
        let pub_hex = ed25519_get_pubkey_hex(priv)
        //let priv = new BN("1234567812345678123456781234567812345678123456781234567812345678", 16)
        //let pub_hex = ed25519_get_pubkey_hex(priv)
        console.log("pub: " + pub_hex)
        let messageHex = "8888888888888888888888888888888888888888888888888888888888888888"
        let sigHex = await ed25519_sign(priv, messageHex)
        console.log("sig : " + sigHex)
        let ok = ed25519_verify(pub_hex, messageHex, sigHex)
        console.log("verify sig: " + ok)
    })
})

describe('ed25519 utils test 2', function () {
    it('hd key test!', async function () {
        let root_xprv = "eprv423G5rKnJnGfjo7ntuhoFLZnrKhngg44vxgyxkZG8GdXBNyatATq9D5vEPuY31EENn2ZUEETtWXVMD9PuXF5buPzMVWEjBoTVPJdFU6bKRW"
        let rootHDKey = Ed25519HDKey.fromExtendedKey(root_xprv);
        let root_xpub = rootHDKey.xpub
        let path = 'm/0/2'
        let messageHex = "8888888888888888888888888888888888888888888888888888888888888888"
        let sigHex = await ed25519_hd_sign(root_xprv, path, messageHex)
        console.log("sig : " + sigHex)
        let ok = ed25519_hd_verify(root_xpub, path, messageHex, sigHex)
        console.log("verify sig: " + ok)


        // start extra test
        let childHDKey = rootHDKey.derive(path)
        console.log('child_xprv: ', childHDKey.xprv)
        console.log('child_xpub: ', childHDKey.xpub)
        let child_pub_hex = childHDKey.publicKeyAsHex
        console.log("child pub: " + child_pub_hex)
        ok = ed25519_verify(child_pub_hex, messageHex, sigHex)
        console.log("verify sig: " + ok)
        // end extra test
    })
})
