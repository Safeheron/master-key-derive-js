import * as BN from "bn.js"
import {Ed25519HDKey, Secp256k1HDKey, P256HDKey} from "@safeheron/crypto-bip32"
import {Hex} from "@safeheron/crypto-utils"
import * as elliptic from "elliptic"
import * as cryptoJS from "crypto-js"
import * as bip39 from 'bip39'
import * as assert from "assert";
import {Rand} from  "@safeheron/crypto-rand"

const utils = elliptic.utils;
const parseBytes = utils.parseBytes;

const Ed25519 = new elliptic.eddsa('ed25519')

export function ed25519_get_pubkey_hex(priv: BN | string): string {
    if (typeof priv === 'string') {
        priv = utils.intFromLE(priv)
    }
    let A = Ed25519.curve.g.mul(priv)
    let A_encode= Ed25519.encodePoint(A);
    return utils.toHex(A_encode)
}

/**
 * ed25519_sign
 * @param priv BN or hex string
 * @param messageHex message in hex string
 */
export async function ed25519_sign(priv: BN | string, messageHex: string): Promise<string> {
    if (typeof priv === 'string') {
        priv = utils.intFromLE(priv)
    }
    let message = parseBytes(messageHex);
    let A = Ed25519.curve.g.mul(priv)
    let r = await Rand.randomBNLt(Ed25519.curve.n)
    let R = Ed25519.curve.g.mul(r);
    let Rencoded = Ed25519.encodePoint(R);
    let s_ = Ed25519.hashInt(Rencoded, Ed25519.encodePoint(A), message).mul(priv);
    let S = r.add(s_).umod(Ed25519.curve.n);
    let sig = Ed25519.makeSignature({R: R, S: S, Rencoded: Rencoded});
    return utils.toHex(sig.Rencoded()) + utils.toHex(sig.Sencoded())
}

/**
 * ed25519_verify
 * @param pubHex public key encode in hex format
 * @param messageHex
 * @param sigHex
 */
export function ed25519_verify(pubHex: string, messageHex: string, sigHex: string): boolean{
    return Ed25519.verify(messageHex, sigHex, pubHex)
}

/**
 * ed25519_hd_sign
 * @param xprv
 * @param path
 * @param messageHex
 */
export async function ed25519_hd_sign(xprv: string, path: string, messageHex: string): Promise<string> {
    let hdKey = Ed25519HDKey.fromExtendedKey(xprv)
    let childHDKey = hdKey.derive(path)
    return await ed25519_sign(childHDKey.privateKey, messageHex)
}

/**
 * ed25519_hd_verify
 * @param xpub
 * @param path
 * @param messageHex
 * @param sigHex
 */
export function ed25519_hd_verify(xpub: string, path: string, messageHex: string, sigHex: string): boolean{
    let hdKey = Ed25519HDKey.fromExtendedKey(xpub)
    let childHDKey = hdKey.derive(path)
    let pubHex = utils.toHex(Ed25519.encodePoint(childHDKey.publicKey))
    return ed25519_verify(pubHex, messageHex, sigHex)
}

