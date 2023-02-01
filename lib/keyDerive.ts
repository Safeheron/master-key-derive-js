import * as BN from "bn.js"
import {Ed25519HDKey, Secp256k1HDKey, P256HDKey} from "@safeheron/crypto-bip32"
import {Hex} from "@safeheron/crypto-utils"
import * as elliptic from "elliptic"
import * as cryptoJS from "crypto-js"
import * as bip39 from 'bip39'
import * as assert from "assert";


const Ed25519 = new elliptic.eddsa('ed25519')
const Secp256k1 = new elliptic.ec('secp256k1')
const P256 = new elliptic.ec('p256')

const ZERO = new BN('0', 16)
const POW2_256= new BN('1', 10).shln(256)

const MASTER_SECRET = cryptoJS.enc.Utf8.parse('MPC seed')

export enum Purpose {
    MASTER_KEY_DERIVE,
    AUTH_KEY_DERIVE,
    POLICY_ENGINE,
}

export enum SigAlg{
    ECDSA_SECP256K1,
    EDDSA_ED25519,
    BLS_BN12_381,
    SCHNORR_SECP256K1,
    ECDSA_P256,
    SCHNORR_P256,
}

function getOrderOfCurve(sigAlg: SigAlg): BN{
    switch (sigAlg) {
        case SigAlg.ECDSA_SECP256K1:
            return Secp256k1.n
        case SigAlg.EDDSA_ED25519:
            return Ed25519.curve.n
        case SigAlg.BLS_BN12_381:
            throw "Unsupported sigAlg:" + sigAlg
        case SigAlg.SCHNORR_SECP256K1:
            return Secp256k1.n
        case SigAlg.ECDSA_P256:
        case SigAlg.SCHNORR_P256:
            return P256.n
        default:
            throw "Unsupported sigAlg:" + sigAlg
    }
}

function getHDKeyClass(sigAlg: SigAlg): any{
    switch (sigAlg) {
        case SigAlg.ECDSA_SECP256K1:
            return Secp256k1HDKey
        case SigAlg.EDDSA_ED25519:
            return Ed25519HDKey
        case SigAlg.BLS_BN12_381:
            throw "Can't get a HDKeyClass because of unsupported sigAlg: " + sigAlg
        case SigAlg.SCHNORR_SECP256K1:
            return Secp256k1HDKey
        case SigAlg.ECDSA_P256:
        case SigAlg.SCHNORR_P256:
            return P256HDKey
        default:
            throw "Can't get a HDKeyClass because of unsupported sigAlg: " + sigAlg
    }
}

function getPurposeHex(purpose: Purpose): string{
    switch (purpose) {
        case Purpose.MASTER_KEY_DERIVE:
            return "00000000"
        case Purpose.AUTH_KEY_DERIVE:
            return "00000001"
        case Purpose.POLICY_ENGINE:
            return "00000002"
        default:
            throw "Unsupported purpose: " + purpose
    }
}

function getSigAlgHex(sigAlg: SigAlg): string{
    switch (sigAlg) {
        case SigAlg.ECDSA_SECP256K1:
            return "00000000"
        case SigAlg.EDDSA_ED25519:
            return "00000001"
        case SigAlg.BLS_BN12_381:
            return "00000002"
        case SigAlg.SCHNORR_SECP256K1:
            return "00000003"
        case SigAlg.ECDSA_P256:
            return "00000004"
        case SigAlg.SCHNORR_P256:
            return "00000005"
        default:
            throw "Unsupported sigAlg:" + sigAlg
    }
}

function getAlternativeHex(alter: number): string{
    return Hex.pad8(alter.toString(16))
}

export class MasterKeyPair {
    public readonly xprv: string;
    public readonly xpub: string;

    public constructor(xprv: string, xpub: string) {
        this.xprv = xprv
        this.xpub = xpub
    }

    public static _checkIsValidChainCode(masterKeyShares: MasterKeyShare[]): boolean{
        assert(masterKeyShares.length > 1)
        // Check the state of 'isFullChainCode'
        let flagFullChainCode = masterKeyShares[0].isFullChainCode
        for(let i = 1; i < masterKeyShares.length; i++){
            if(masterKeyShares[i].isFullChainCode !== flagFullChainCode){
                return false
            }
        }
        return true
    }
    public static _checkIsFullChainCode(masterKeyShares: MasterKeyShare[]): boolean{
        assert(masterKeyShares.length > 1)
        let c = masterKeyShares[0].chainCodeShare
        for(let i = 1; i < masterKeyShares.length; i++){
            if(!masterKeyShares[i].chainCodeShare.eq(c)){
                return false
            }
        }
        return true
    }

    /**
     * Recover master key pair from all the MasterKeyShares
     * @param masterKeyShares
     * @param sigAlg
     */
    public static recoverFromMasterKeyShares(masterKeyShares: MasterKeyShare[], sigAlg: SigAlg): MasterKeyPair{
        assert(masterKeyShares.length > 1)
        let n = getOrderOfCurve(sigAlg)
        let c = new BN(0)
        let k = new BN(0)
        for(let mks of masterKeyShares){
            c = c.add(mks.chainCodeShare).umod(POW2_256)
            k = k.add(mks.keyShare).umod(n)
        }

        if(k.eqn(0)) throw "Invalid master key!"

        if(MasterKeyPair._checkIsFullChainCode(masterKeyShares)) {
            c = masterKeyShares[0].chainCodeShare
        }

        let HDKeyClass = getHDKeyClass(sigAlg)
        let hdKey = HDKeyClass.fromPrivateKeyAndChainCode(k, c)
        return new MasterKeyPair(hdKey.xprv, hdKey.xpub)
    }

    private static _recoverFromMnemonics(mnemonics: Mnemonics[], sigAlg: SigAlg, alt): MasterKeyPair{
        let masterKeyShares: MasterKeyShare[] = []
        for(let i = 0; i < mnemonics.length; i++){
            masterKeyShares.push(mnemonics[i].derive(Purpose.MASTER_KEY_DERIVE, sigAlg, alt))
        }
        if (!MasterKeyPair._checkIsValidChainCode(masterKeyShares)) throw 'Invalid chain code!'
        try{
            return MasterKeyPair.recoverFromMasterKeyShares(masterKeyShares, sigAlg)
        }catch (err){
            return MasterKeyPair._recoverFromMnemonics(mnemonics, sigAlg, alt+1)
        }
    }

    /**
     * Recover master key pair from all the Mnemonics
     * @param mnemonics
     * @param sigAlg
     */
    public static recoverFromMnemonics(mnemonics: Mnemonics[], sigAlg: SigAlg): MasterKeyPair{
        return MasterKeyPair._recoverFromMnemonics(mnemonics, sigAlg, 0)
    }
}

export class MasterKeyShare{
    public readonly keyShare: BN;
    public readonly chainCodeShare: BN;
    public readonly isFullChainCode: boolean;

    public constructor(keyShare: BN, chainCodeShare: BN, isFullChainCode: boolean) {
        this.keyShare = keyShare
        this.chainCodeShare = chainCodeShare
        this.isFullChainCode = isFullChainCode
    }
}

export class Mnemonics{
    public readonly mnemo: string;
    public readonly extraMnemo: string;

    public constructor(mnemo: string, extraMnemo: string) {
        assert(mnemo.length > 0)
        this.mnemo = mnemo
        this.extraMnemo = extraMnemo
    }

    /***
     * Create Mnemonics from key share and chain code.
     *
     * Warn: only invoked by the old user of mpc wallet
     *
     * @param keyShare
     * @param chainCode
     */
    public static createMnemonics(keyShare: BN, chainCode: BN) : Mnemonics{
        assert(chainCode.lt(POW2_256))
        assert(keyShare.lt(Secp256k1.n))
        let mnemo = bip39.entropyToMnemonic(Hex.pad64(keyShare.toString(16)))
        let extraMnemo = bip39.entropyToMnemonic(Hex.pad64(chainCode.toString(16)))
        return new Mnemonics(mnemo, extraMnemo)
    }

    /**
     * Create a new Mnemonic
     */
    public static generateMnemonic(): Mnemonics{
        let mnemo = bip39.generateMnemonic(256)
        return new Mnemonics(mnemo, "")
    }

    private _derive(purpose: Purpose, sigAlg: SigAlg, alg: number): MasterKeyShare{
        let seedHex = bip39.mnemonicToEntropy(this.mnemo)
        let purposeHex = getPurposeHex(purpose)
        let sigAlgHex = getSigAlgHex(sigAlg)
        let alternativeHex = getAlternativeHex(alg)

        // Derivation 0
        let keyBytes = MASTER_SECRET
        let dataBytes = cryptoJS.enc.Hex.parse(seedHex)
        let IHex = cryptoJS.enc.Hex.stringify(cryptoJS.HmacSHA512(dataBytes, keyBytes))
        let IL_hex = IHex.substr(0, 64)
        let IR_hex = IHex.substr(64)

        // Derivation 1
        keyBytes = cryptoJS.enc.Hex.parse(IL_hex)
        dataBytes = cryptoJS.enc.Hex.parse(IR_hex + purposeHex)
        IHex = cryptoJS.enc.Hex.stringify(cryptoJS.HmacSHA512(dataBytes, keyBytes))
        IL_hex = IHex.substr(0, 64)
        IR_hex = IHex.substr(64)

        // Derivation 2
        keyBytes = cryptoJS.enc.Hex.parse(IL_hex)
        dataBytes = cryptoJS.enc.Hex.parse(IR_hex + sigAlgHex)
        IHex = cryptoJS.enc.Hex.stringify(cryptoJS.HmacSHA512(dataBytes, keyBytes))
        IL_hex = IHex.substr(0, 64)
        IR_hex = IHex.substr(64)

        // Derivation 3
        keyBytes = cryptoJS.enc.Hex.parse(IL_hex)
        dataBytes = cryptoJS.enc.Hex.parse(IR_hex + alternativeHex)
        IHex = cryptoJS.enc.Hex.stringify(cryptoJS.HmacSHA512(dataBytes, keyBytes))
        IL_hex = IHex.substr(0, 64)
        IR_hex = IHex.substr(64)

        let IL = new BN(0)
        let IR = new BN(0)
        if(sigAlg === SigAlg.EDDSA_ED25519){
            // IL: little-endian
            IL = new BN(Hex.reverseHex(IL_hex), 16)
            // It doesn't matter for iR's encode.
            IR = new BN(IR_hex, 16)
        }else{
            IL = new BN(IL_hex, 16)
            IR = new BN(IR_hex, 16)
        }

        let n = getOrderOfCurve(sigAlg)
        let k = IL.umod(n)
        let c = IR
        if(k.eqn(0)) {
            return this._derive(purpose, sigAlg, alg + 1)
        }

        return new MasterKeyShare(k, c, false)
    }

    private _derive_old_secp256k1(): MasterKeyShare{
        let n = getOrderOfCurve(SigAlg.ECDSA_SECP256K1)
        let k = new BN(bip39.mnemonicToEntropy(this.mnemo), 16)
        k = k.umod(n)
        let c = new BN(bip39.mnemonicToEntropy(this.extraMnemo), 16)
        return new MasterKeyShare(k, c, true)
    }

    /**
     * Derive function
     * @param purpose
     * @param sigAlg
     * @param alg
     */
    public derive(purpose: Purpose, sigAlg: SigAlg, alg: number): MasterKeyShare{
        if(this.extraMnemo === undefined || this.extraMnemo === ""){
            return this._derive(purpose, sigAlg, alg)
        }else{
            return this._derive_old_secp256k1()
        }
    }

}

export function mnemonicToExtendedPub(sigAlg: SigAlg, alt: number, mnemo: string, chaincode: string = ""): string {
    let HDKeyClass = getHDKeyClass(sigAlg)
    let extraMnemo = ""
    if (chaincode !== "") {
        if (sigAlg !== SigAlg.ECDSA_SECP256K1) throw 'Invalid sign algorithm!'
        extraMnemo = bip39.entropyToMnemonic(Hex.pad64(chaincode))
    }
    let mnemoObj = new Mnemonics(mnemo, extraMnemo);
    let masterKeyShare = mnemoObj.derive(Purpose.MASTER_KEY_DERIVE, sigAlg, alt)
    let hdKey = HDKeyClass.fromPrivateKeyAndChainCode(masterKeyShare.keyShare, masterKeyShare.chainCodeShare)
    return hdKey.xpub
}

export function extendedPubSharesAgg(sigAlg: SigAlg, extendedPubShares: string[], isFullChainCode: boolean): string {
    assert(extendedPubShares.length > 1)
    let HDKeyClass = getHDKeyClass(sigAlg)

    let hdKey = HDKeyClass.fromExtendedKey(extendedPubShares[0])
    let chaincode = hdKey.chainCode
    let pub = hdKey.publicKey

    for(let i = 1; i < extendedPubShares.length; i++){
        hdKey = HDKeyClass.fromExtendedKey(extendedPubShares[i])
        pub = pub.add(hdKey.publicKey)
        if (isFullChainCode) {
            if (!chaincode.eq(hdKey.chainCode)) throw "Invalid chaincode!"
        } else {
            chaincode = chaincode.add(hdKey.chainCode).umod(POW2_256)
        }
    }

    if (pub.isInfinity()) throw "Invalid master public key!"

    hdKey = HDKeyClass.fromPublicKeyAndChainCode(pub, chaincode)
    return hdKey.xpub
}
