# Master Key Derive
# Installation
```shell
npm install @safeheron/master-key-derive
```

# Examples
## For fresh users
```javascript
import {Mnemonics, MasterKeyShare, MasterKeyPair, Purpose, SigAlg} from "@safeheron/master-key-derive"

// Generate a random mnemonic, default 24 words
// let mnemo1 = new Mnemonics("two amazing rule deliver novel silly vital evolve bacon wasp drill circle consider prize canyon marriage junk warm summer action bid hole find fringe", "")
let mnemo1 = Mnemonics.generateMnemonic()
// => mnemo: 'two amazing rule deliver novel silly vital evolve bacon wasp drill circle consider prize canyon marriage junk warm summer action bid hole find fringe'
// => extraMnemo: ''

let masterKeyShare1 = mnemo1.derive(Purpose.MASTER_KEY_DERIVE, SigAlg.EDDSA_ED25519, 0)
// => ks:  9181650b0677806fb5678fedc72f881758b31eb55c7f0cf5afa321c37bf66b
// => cs:  5469a1ffbb37f3dcbeb9ad1235f23b49641b1089a73a5c025db53c6b03eb64b1

// Generate a random mnemonic, default 24 words
let mnemo2 = Mnemonics.generateMnemonic()
// => mnemo: 'swamp phone eight assume wasp short keep flash zoo response venue rescue foam that memory rather output zoo eternal phrase such climb expand upper'
// => extraMnemo: ''

let masterKeyShare2 = mnemo2.derive(Purpose.MASTER_KEY_DERIVE, SigAlg.EDDSA_ED25519, 0)
// => ks:  be2f809f659d539d9b890086ec98b8bbbea7aa3296740d45380d968fcb72ae2
// => cs:  542c017a6f40ca97ccc92a5702a34e46aacaaf21c31efae716674c9689cd89c5

// Generate a random mnemonic, default 24 words
let mnemo3 = Mnemonics.generateMnemonic()
// => mnemo:  'easily mind staff drip shell oblige where exile proof design road bench surface public sea season rabbit bargain lab shaft myth library music alone'
// => extraMnemo:
    
let masterKeyShare3 = mnemo3.derive(Purpose.MASTER_KEY_DERIVE, SigAlg.EDDSA_ED25519, 0)
// => ks:  9adb4f8d887765277a4e5c912406fe172e9711bc422acbbfbdf8e3dec9779f9
// => cs:  cad511d5c92e96b8d2686b62044d8195a389900bab61f22940696598408733b4

let masterKeyPair = MasterKeyPair.recoverFromMasterKeyShares([masterKeyShare1, masterKeyShare2, masterKeyShare3], SigAlg.EDDSA_ED25519)
// => xpriv: 'eprv423G5rKnJnGfjsZ6m8ug6gEuqrPm1UxsRCfsYq4PgrnxhdzLaUGCwTkTrHcArt9aj7eYaHBZUKkz4JzyJaqcr3DwvAgMEJP4tAGgTiGnjTS',
// => xpub: 'epub8YjJEGN2T9xLdLatenaGW5u2QsuhAp9mzWGeqM6h78bMY8F7Cs5o7xNL2LWFdUAfHR83BABkB2ucwaDYrx4bFu6g64i7fppyBdL9c2GVjiu'

let expected_masterKeyPair = MasterKeyPair.recoverFromMnemonics([mnemo1, mnemo2, mnemo3], SigAlg.EDDSA_ED25519)
// => xpriv: 'eprv423G5rKnJnGfjsZ6m8ug6gEuqrPm1UxsRCfsYq4PgrnxhdzLaUGCwTkTrHcArt9aj7eYaHBZUKkz4JzyJaqcr3DwvAgMEJP4tAGgTiGnjTS',
// => xpub: 'epub8YjJEGN2T9xLdLatenaGW5u2QsuhAp9mzWGeqM6h78bMY8F7Cs5o7xNL2LWFdUAfHR83BABkB2ucwaDYrx4bFu6g64i7fppyBdL9c2GVjiu'
```

## For old user

```javascript
import {Mnemonics, MasterKeyShare, MasterKeyPair, Purpose, SigAlg} from "@safeheron/master-key-derive"

let chainCode1 = new BN("5555555555555555555555555555555555555555555555555555555555555555")
let keyShare1 = new BN("1111111111111111111111111111111111111111111111111111111111111111")
let masterKeyShare1 = new MasterKeyShare(keyShare1, chainCode1, true)
// => ks:  2b372365c711b34bd49c50c3f36d24e283c5571c71c71c71c71c7
// => cs:  d813b0fce358807b270d93d3c121b86c92dab38e38e38e38e38e3

let chainCode2 = new BN("5555555555555555555555555555555555555555555555555555555555555555")
let keyShare2 = new BN("2222222222222222222222222222222222222222222222222222222222222222")
let masterKeyShare2 = new MasterKeyShare(keyShare2, chainCode2, true)
// => ks:  566e46cb8e236697a938a187e6da49c5078aae38e38e38e38e38e
// => cs:  d813b0fce358807b270d93d3c121b86c92dab38e38e38e38e38e3

let chainCode3 = new BN("5555555555555555555555555555555555555555555555555555555555555555")
let keyShare3 = new BN("3333333333333333333333333333333333333333333333333333333333333333")
let masterKeyShare3 = new MasterKeyShare(keyShare3, chainCode3, true)
// => ks:  81a56a31553519e37dd4f24bda476ea78b5005555555555555555
// => cs:  d813b0fce358807b270d93d3c121b86c92dab38e38e38e38e38e3

// Recover the master key from key share
let masterKeyPair = MasterKeyPair.recoverFromMasterKeyShares([masterKeyShare1, masterKeyShare2, masterKeyShare3], SigAlg.ECDSA_SECP256K1)
// => xpriv: 'xprv9s21ZrQH143K24Mfq5zLtLamyQWyjuS5crnUNZVdF8qigqXCmCpTk1CgbqAcMbGScFtb5hhp2AdN16kyaMHeTZb7WMtfQsvFJPQeRPJHoFP',
// => xpub: 'xpub661MyMwAqRbcEYS8w7XMFUXWXSMU9N9vz5i5AwuEoUNhZdrMJk8iHoXAT99hQetcYpq446gPkZnhdYcyXNLq7d6y8xqDSGqVtYkXjRimyCG'

let mnemo1 = Mnemonics.createMnemonics(keyShare1, chainCode1)
// => mnemo:  abandon abandon abandon abandon clinic ribbon sunny mixed brass planet fame meat sentence opinion empty shallow detail process impact decline broccoli mixed shove twenty
// => extraMnemo:  abandon abandon abandon abandon submit outside dish shop marine diesel order raven stable animal host summer color flush decline broccoli mixed shove toe immense

let mnemo2 = Mnemonics.createMnemonics(keyShare2, chainCode2)
// => mnemo:  abandon abandon abandon abandon filter impulse real brisk cushion envelope pilot before margin cycle mystery meat judge finish toe impact decline broccoli mixed stereo
// => extraMnemo:  abandon abandon abandon abandon submit outside dish shop marine diesel order raven stable animal host summer color flush decline broccoli mixed shove toe immense

let mnemo3 = Mnemonics.createMnemonics(keyShare3, chainCode3)
// => mnemo:  abandon abandon abandon abandon like clip middle price face vast warrior oxygen envelope split sweet excuse relax actor fetch primary fetch primary fetch reason
// => extraMnemo:  abandon abandon abandon abandon submit outside dish shop marine diesel order raven stable animal host summer color flush decline broccoli mixed shove toe immense

// Recover the master key from mnemonics
let expected_masterKeyPair = MasterKeyPair.recoverFromMnemonics([mnemo1, mnemo2, mnemo3], SigAlg.ECDSA_SECP256K1)
// => xpriv: 'xprv9s21ZrQH143K24Mfq5zLtLamyQWyjuS5crnUNZVdF8qigqXCmCpTk1CgbqAcMbGScFtb5hhp2AdN16kyaMHeTZb7WMtfQsvFJPQeRPJHoFP',
// => xpub: 'xpub661MyMwAqRbcEYS8w7XMFUXWXSMU9N9vz5i5AwuEoUNhZdrMJk8iHoXAT99hQetcYpq446gPkZnhdYcyXNLq7d6y8xqDSGqVtYkXjRimyCG'

console.assert(masterKeyPair.xpub === expected_masterKeyPair.xpub)
// => true
console.assert(masterKeyPair.xpriv === expected_masterKeyPair.xpriv)
// => true
```
