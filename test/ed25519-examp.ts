'use strict'
import BN = require('bn.js')
import {MasterKeyPair, MasterKeyShare, Mnemonics, Purpose, SigAlg} from ".."
import 'mocha'

describe('For fresh users', function () {
    it('Random Mnemonic!', function () {
// => mnemonics: two amazing rule deliver novel silly vital evolve bacon wasp drill circle consider prize canyon marriage junk warm summer action bid hole find fringe
// => extraMnemo:
// => ks:  9181650b0677806fb5678fedc72f881758b31eb55c7f0cf5afa321c37bf66b
// => cs:  5469a1ffbb37f3dcbeb9ad1235f23b49641b1089a73a5c025db53c6b03eb64b1
        let mnemo1 = new Mnemonics("two amazing rule deliver novel silly vital evolve bacon wasp drill circle consider prize canyon marriage junk warm summer action bid hole find fringe", "")
        let ks1 = "9181650b0677806fb5678fedc72f881758b31eb55c7f0cf5afa321c37bf66b"
        let cs1 = "5469a1ffbb37f3dcbeb9ad1235f23b49641b1089a73a5c025db53c6b03eb64b1"
        let masterKeyShare1 = mnemo1.derive(Purpose.MASTER_KEY_DERIVE, SigAlg.EDDSA_ED25519, 0)
        console.assert(masterKeyShare1.keyShare.toString(16) === ks1)
        console.assert(masterKeyShare1.chainCodeShare.toString(16) === cs1)

// => mnemonics: swamp phone eight assume wasp short keep flash zoo response venue rescue foam that memory rather output zoo eternal phrase such climb expand upper
// => extraMnemo:
// => ks:  be2f809f659d539d9b890086ec98b8bbbea7aa3296740d45380d968fcb72ae2
// => cs:  542c017a6f40ca97ccc92a5702a34e46aacaaf21c31efae716674c9689cd89c5
        let mnemo2 = new Mnemonics("swamp phone eight assume wasp short keep flash zoo response venue rescue foam that memory rather output zoo eternal phrase such climb expand upper", "")
        let ks2 = "be2f809f659d539d9b890086ec98b8bbbea7aa3296740d45380d968fcb72ae2"
        let cs2 = "542c017a6f40ca97ccc92a5702a34e46aacaaf21c31efae716674c9689cd89c5"
        let masterKeyShare2 = mnemo2.derive(Purpose.MASTER_KEY_DERIVE, SigAlg.EDDSA_ED25519, 0)
        console.assert(masterKeyShare2.keyShare.toString(16) === ks2)
        console.assert(masterKeyShare2.chainCodeShare.toString(16) === cs2)

// => mnemonics: easily mind staff drip shell oblige where exile proof design road bench surface public sea season rabbit bargain lab shaft myth library music alone
// => extraMnemo:
// => ks:  9adb4f8d887765277a4e5c912406fe172e9711bc422acbbfbdf8e3dec9779f9
// => cs:  cad511d5c92e96b8d2686b62044d8195a389900bab61f22940696598408733b4
        let mnemo3 = new Mnemonics("easily mind staff drip shell oblige where exile proof design road bench surface public sea season rabbit bargain lab shaft myth library music alone", "")
        let ks3 = "9adb4f8d887765277a4e5c912406fe172e9711bc422acbbfbdf8e3dec9779f9"
        let cs3 = "cad511d5c92e96b8d2686b62044d8195a389900bab61f22940696598408733b4"
        let masterKeyShare3 = mnemo3.derive(Purpose.MASTER_KEY_DERIVE, SigAlg.EDDSA_ED25519, 0)
        console.assert(masterKeyShare3.keyShare.toString(16) === ks3)
        console.assert(masterKeyShare3.chainCodeShare.toString(16) === cs3)

// => xpriv: 'eprv423G5rKnJnGfjsZ6m8ug6gEuqrPm1UxsRCfsYq4PgrnxhdzLaUGCwTkTrHcArt9aj7eYaHBZUKkz4JzyJaqcr3DwvAgMEJP4tAGgTiGnjTS',
// => xpub: 'epub8YjJEGN2T9xLdLatenaGW5u2QsuhAp9mzWGeqM6h78bMY8F7Cs5o7xNL2LWFdUAfHR83BABkB2ucwaDYrx4bFu6g64i7fppyBdL9c2GVjiu'
        let xprv = "eprv423G5rKnJnGfjsZ6m8ug6gEuqrPm1UxsRCfsYq4PgrnxhdzLaUGCwTkTrHcArt9aj7eYaHBZUKkz4JzyJaqcr3DwvAgMEJP4tAGgTiGnjTS"
        let xpub = "epub8YjJEGN2T9xLdLatenaGW5u2QsuhAp9mzWGeqM6h78bMY8F7Cs5o7xNL2LWFdUAfHR83BABkB2ucwaDYrx4bFu6g64i7fppyBdL9c2GVjiu"

        let masterKeyPair = MasterKeyPair.recoverFromMasterKeyShares([masterKeyShare1, masterKeyShare2, masterKeyShare3], SigAlg.EDDSA_ED25519)
        console.log(masterKeyPair)
        console.assert(masterKeyPair.xprv === xprv)
        console.assert(masterKeyPair.xpub === xpub)

        let expected_masterKeyPair = MasterKeyPair.recoverFromMnemonics([mnemo1, mnemo2, mnemo3], SigAlg.EDDSA_ED25519)
        console.log(expected_masterKeyPair)
        console.assert(expected_masterKeyPair.xprv === xprv)
        console.assert(expected_masterKeyPair.xpub === xpub)
    })
})
